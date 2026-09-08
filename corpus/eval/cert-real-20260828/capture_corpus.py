#!/usr/bin/env python3
"""Freeze a real CNSD/ColCERT corpus without invoking an LLM or OpenCTI.

The production collector performs the confined collection -> landing -> PDF
traversal. This script only selects unseen documents, parses their PDF bytes
with the production parser, and writes immutable experimental inputs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


DEFAULT_SOURCE_NAMES = [
    "CNSD Integrated Digital Security Alerts",
    "ColCERT Boletines",
]
DISCOVERY_LIMIT = 12
# Conservative character guard for a 200K-token model. This is intentionally
# lower than parser.MAX_TEXT_CHARS: the parser cap protects memory/cost, not the
# model context window.
MAX_EXPERIMENT_TEXT_CHARS = 600_000


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_prefix(name: str) -> str:
    if name.startswith("CNSD"):
        return "cnsd"
    if name.startswith("ColCERT"):
        return "colcert"
    return re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:24]


def _stem(source_name: str, publication_date: str, document_url: str) -> str:
    suffix = _sha256(document_url.encode("utf-8"))[:10]
    return f"{_source_prefix(source_name)}-{publication_date}-{suffix}"


def _seed_urls(source: dict) -> set[str]:
    return {
        value
        for row in source.get("processed_seed_documents", [])
        for value in (row.get("landing_url"), row.get("document_url"))
        if value
    }


def _select(source: dict, documents: Iterable[object], per_source: int) -> list[object]:
    seeds = _seed_urls(source)
    selected = []
    seen_documents = set()
    for document in documents:
        landing_url = getattr(document, "landing_dedup_key", None)
        document_url = getattr(document, "document_dedup_key", None)
        if not document_url or document_url in seen_documents:
            continue
        seen_documents.add(document_url)
        if landing_url in seeds or document_url in seeds:
            continue
        selected.append(document)
        if len(selected) == per_source:
            break
    if len(selected) != per_source:
        raise ValueError(
            f"{source['name']}: expected {per_source} unseen PDF documents, "
            f"found {len(selected)}"
        )
    return selected


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def capture(
    source_names: list[str],
    per_source: int,
    output_dir: Path,
    *,
    sources: list[dict],
    discover: Callable,
    parse_pdf_text: Callable[[bytes], str],
    now_utc: str,
) -> dict:
    """Capture exactly ``per_source`` unseen PDFs for every named source."""
    if per_source < 1:
        raise ValueError("per_source must be positive")
    by_name = {source.get("name"): source for source in sources}
    if len(by_name) != len(sources):
        raise ValueError("source names must be unique")
    missing = [name for name in source_names if name not in by_name]
    if missing:
        raise ValueError(f"configured sources not found: {', '.join(missing)}")

    prepared: list[tuple[object, dict, bytes, bytes]] = []
    all_urls: set[str] = set()
    discovery_errors: dict[str, list[str]] = {}

    for source_name in source_names:
        source = copy.deepcopy(by_name[source_name])
        source["max_candidates"] = max(DISCOVERY_LIMIT, int(source.get("max_candidates", 0)))
        result = discover(source, state={}, limit=DISCOVERY_LIMIT, operational=False)
        discovery_errors[source_name] = list(getattr(result, "errors", []))
        for document in _select(source, result.documents, per_source):
            content = getattr(document, "content", None)
            if not isinstance(content, bytes) or not content.lstrip().startswith(b"%PDF-"):
                raise ValueError(f"{source_name}: document body is not a confirmed PDF")
            document_url = getattr(document, "document_dedup_key", None)
            if document_url in all_urls:
                raise ValueError(f"duplicate document URL across sources: {document_url}")
            all_urls.add(document_url)
            text = parse_pdf_text(content)
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"{source_name}: parser returned empty text")
            if len(text) > MAX_EXPERIMENT_TEXT_CHARS:
                raise ValueError(
                    f"{source_name}: parsed text exceeds experimental context guard "
                    f"({len(text)} > {MAX_EXPERIMENT_TEXT_CHARS} characters)"
                )
            text_bytes = text.encode("utf-8")
            publication_date = getattr(document, "publication_date", None)
            if not isinstance(publication_date, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}", publication_date
            ):
                raise ValueError(f"{source_name}: missing normalized publication date")
            metadata = {
                "source_name": source_name,
                "title": getattr(document, "title", None),
                "publication_date": publication_date,
                "landing_url": getattr(document, "landing_dedup_key", None),
                "document_url": document_url,
                "title_source": getattr(document, "title_source", None),
                "publication_date_source": getattr(document, "publication_date_source", None),
                "selection_order": len([p for p in prepared if p[1]["source_name"] == source_name]) + 1,
                "selection_rule": "first unseen eligible PDF in collection order",
                "sha256_pdf": _sha256(content),
                "sha256_text": _sha256(text_bytes),
                "pdf_bytes": len(content),
                "text_chars": len(text),
                "llm_calls": 0,
                "opencti_writes": 0,
            }
            metadata["stem"] = _stem(source_name, publication_date, document_url)
            prepared.append((document, metadata, content, text_bytes))

    if len(prepared) != len(source_names) * per_source:
        raise ValueError("captured corpus size does not match the frozen design")

    output_dir = Path(output_dir)
    documents_dir = output_dir / "documents"
    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists() or documents_dir.exists():
        raise FileExistsError("frozen corpus already exists; refusing to overwrite it")

    documents_dir.mkdir(parents=True)
    rows = []
    for _document, metadata, content, text_bytes in prepared:
        folder = documents_dir / metadata["stem"]
        folder.mkdir()
        (folder / "source.pdf").write_bytes(content)
        (folder / "input.txt").write_bytes(text_bytes)
        _atomic_json(folder / "metadata.json", metadata)
        rows.append(metadata)

    manifest = {
        "protocol_version": 1,
        "created_at_utc": now_utc,
        "selection_rule": "two newest unseen eligible PDFs per configured collection",
        "per_source": per_source,
        "source_names": source_names,
        "llm_calls": 0,
        "opencti_writes": 0,
        "discovery_limit_per_source": DISCOVERY_LIMIT,
        "context_guard_chars": MAX_EXPERIMENT_TEXT_CHARS,
        "discovery_errors": discovery_errors,
        "documents": rows,
    }
    _atomic_json(manifest_path, manifest)
    return manifest


def _runtime_dependencies():
    project_root = Path(__file__).resolve().parents[3]
    service_dir = project_root / "services" / "intel-extractor"
    sys.path.insert(0, str(service_dir))
    import collector
    import parser

    return collector._load_sources(), collector.discover_html_collection, parser.extract_pdf_text


def main() -> int:
    parser_cli = argparse.ArgumentParser()
    parser_cli.add_argument("--per-source", type=int, default=2)
    parser_cli.add_argument("--output", type=Path, default=Path(__file__).parent)
    args = parser_cli.parse_args()
    sources, discover, parse_pdf_text = _runtime_dependencies()
    manifest = capture(
        source_names=DEFAULT_SOURCE_NAMES,
        per_source=args.per_source,
        output_dir=args.output,
        sources=sources,
        discover=discover,
        parse_pdf_text=parse_pdf_text,
        now_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
