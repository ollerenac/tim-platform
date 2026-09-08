"""
anchor.py — verificación de anclaje de síntesis (2026-08-19).

Cada identificador detectable del texto generado (IP, dominio, URL, CVE o TID
ATT&CK) se busca en el contexto DATA que vio el modelo. Es un control léxico,
no un verificador general de verdad: no valida nombres, relaciones,
atribuciones, conteos ni afirmaciones cualitativas.

Los dominios exigen un sufijo de la lista pública congelada. Un token como
`loader.py` sigue siendo ambiguo porque `.py` es también un TLD registrado;
el control lo marca para revisión si no aparece en el contexto.

En el PoC del 18-ago marcó dos URL sin coincidencia exacta. La revisión humana
adjudicó una como fabricación (aone-cli frente a aone-ai-cli) y la otra como
URL raíz derivada. Ver corpus/eval/sintetizador/.
"""
import re
from urllib.parse import urlsplit, urlunsplit

from iana_tlds import FROZEN_TLDS

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TID_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_URL_RE = re.compile(r"https?://[^\s|)\]}>\"'`]+", re.I)
_DOM_RE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b")


def _normalized_identifier(kind: str, value: str) -> str:
    """Normaliza solo las partes cuya caja no es semántica para cada tipo."""
    if kind == "url":
        parsed = urlsplit(value)
        return urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.query,
            parsed.fragment,
        ))
    if kind == "dominio":
        return value.lower()
    if kind in {"cve", "tid"}:
        return value.upper()
    return value


def _hard_facts(text: str) -> list[tuple[str, str]]:
    """Extrae identificadores detectables. Tolera Markdown y puntuación."""
    facts: list[tuple[str, str]] = []
    facts += [("ipv4", value) for value in _IP_RE.findall(text)]
    facts += [("tid", value) for value in _TID_RE.findall(text)]
    facts += [("cve", value) for value in _CVE_RE.findall(text)]
    url_matches = list(_URL_RE.finditer(text))
    urls = [match.group().rstrip(".,;:*") for match in url_matches]
    facts += [("url", u) for u in urls]
    doms = [
        match.group()
        for match in _DOM_RE.finditer(text.lower())
        if match.group().rsplit(".", 1)[-1] in FROZEN_TLDS
        if not any(
            match.start() >= url.start() and match.end() <= url.end()
            for url in url_matches
        )
    ]
    facts += [("dominio", d) for d in doms]
    unique = {
        (kind, _normalized_identifier(kind, value))
        for kind, value in facts
    }
    return sorted(unique)


def _context_identifiers(context: str) -> set[tuple[str, str]]:
    """Índices exactos del contexto; un host URL también sustenta dominio/IP."""
    facts = _hard_facts(context)
    identifiers = {
        (kind, _normalized_identifier(kind, value))
        for kind, value in facts
    }
    for kind, value in facts:
        if kind != "url":
            continue
        host = urlsplit(value).hostname
        if not host:
            continue
        host_kind = "ipv4" if _IP_RE.fullmatch(host) else "dominio"
        identifiers.add((host_kind, _normalized_identifier(host_kind, host)))
    return identifiers


def find_unanchored(text: str, context: str) -> list[tuple[str, str]]:
    """Identificadores de ``text`` ausentes de ``context`` para revisión."""
    context_ids = _context_identifiers(context)
    return sorted(
        (kind, value)
        for kind, value in _hard_facts(text)
        if (kind, _normalized_identifier(kind, value)) not in context_ids
    )


def anchor_stats(text: str, context: str) -> dict:
    """Resumen persistible de la verificación: totales y no-anclados.

    Alimenta la columna `anchor` del store, el badge del dashboard y el
    harness de eval. `total_facts` se conserva por compatibilidad del API; su
    contenido es el total de identificadores detectados, no hechos semánticos.
    """
    total = len(_hard_facts(text))
    bad = find_unanchored(text, context)
    return {
        "total_facts": total,
        "unanchored": [f"{k}:{v}" for k, v in bad],
    }
