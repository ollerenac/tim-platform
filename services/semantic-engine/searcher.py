"""
searcher.py — ChromaDB query + similarity score conversion for semantic-engine.

RESEARCH Pitfall 1 (HIGH IMPACT): ChromaDB returns cosine DISTANCE (0=identical,
higher=more different). Similarity = 1 - distance. Filter on score < threshold,
NOT on dist > threshold.
"""
import logging

import ollama

from config import (
    OLLAMA_EMBED_MODEL,
    OLLAMA_KEEP_ALIVE,
    OLLAMA_SEARCH_TIMEOUT_SECONDS,
    OLLAMA_URL,
)
from indexer import WATERMARK_ID

logger = logging.getLogger(__name__)


def create_ollama_client(client_factory=None):
    """Build the query client with enough budget for a cold embedding-model load."""
    factory = client_factory if client_factory is not None else ollama.Client
    return factory(host=OLLAMA_URL, timeout=OLLAMA_SEARCH_TIMEOUT_SECONDS)


# ponytail: module-level singleton; tests inject via monkeypatch.setattr(searcher, "_ollama", ...)
# The 90-second inner timeout remains below the verifier's 120-second HTTP budget.
_ollama = create_ollama_client()


def embed_query(text: str, ollama_client=None) -> list:
    """Embed a query string. Uses ollama_client if provided (for tests), else _ollama."""
    client = ollama_client if ollama_client is not None else _ollama
    response = client.embed(
        model=OLLAMA_EMBED_MODEL,
        input=text,
        keep_alive=OLLAMA_KEEP_ALIVE,
    )
    if not response.embeddings or not response.embeddings[0]:
        raise RuntimeError("Ollama returned no embedding vector")
    return response.embeddings[0]  # plural — not deprecated .embedding singular (Pitfall 4)


def warmup(ollama_client=None) -> int:
    """Load the embedding model and prove it returned a usable vector."""
    dimensions = len(embed_query("TIM semantic readiness", ollama_client))
    logger.info(
        "[semantic-readiness] model %s warm with %d dimensions",
        OLLAMA_EMBED_MODEL,
        dimensions,
    )
    return dimensions


def search(
    collection,
    query: str,
    ollama_client=None,
    n_results: int = 10,
    threshold: float = 0.3,
) -> list:
    """
    Query ChromaDB and return results with similarity scores above threshold.

    score = round(1.0 - distance, 4)  — RESEARCH Pitfall 1: distance ≠ similarity
    Filters on score < threshold (not on raw distance).
    ChromaDB returns results ordered by distance ascending (most similar first),
    so output list is already ranked by score descending.
    """
    query_vec = embed_query(query, ollama_client)
    raw = collection.query(
        query_embeddings=[query_vec],
        n_results=n_results,
        include=["distances", "metadatas", "documents"],
    )

    output = []
    ids = raw.get("ids", [[]])[0]
    for i, (dist, meta) in enumerate(zip(raw["distances"][0], raw["metadatas"][0])):
        # Skip the watermark sentinel: its zero-vector yields a NaN distance (NaN < threshold
        # is False, so it wouldn't be dropped) and its metadata has no ioc_type → KeyError 500.
        if i < len(ids) and ids[i] == WATERMARK_ID:
            continue
        if "ioc_type" not in meta:
            continue
        score = round(1.0 - dist, 4)
        if score < threshold:  # D-07: drop low-similarity results
            continue
        output.append({
            "ioc_type": meta["ioc_type"],
            "value": meta.get("value", ""),
            "author": meta.get("author", ""),  # provenance (curated index v2)
            "score": score,
            "opencti_url": meta.get("opencti_url", ""),
            "embedded_text": meta.get("embedded_text", ""),  # D-08
        })
    return output
