"""
entity_resolver.py — deterministic closed-world resolution for LLM targeting output.

Fase A (design 260724-fa): the extractor LINKS to known entities, it never invents
them. Every candidate name the LLM emits is resolved against a catalog before it may
reach the graph:

  actors   → live Intrusion-Set catalog in OpenCTI (names + aliases)
  malware  → live Malware catalog in OpenCTI (names + aliases)
  sectors  → fixed canonical taxonomy (EN/ES synonyms)
  countries→ fixed ISO-derived list (EN/ES + common abbreviations)

Matching is deliberately conservative: exact casefold after light normalization
(strip a leading article, edge punctuation, collapsed whitespace). NO fuzzy matching —
a false merge poisons the graph worse than a miss, and misses are queued, not lost.

Catalog fetch is fail-closed: if OpenCTI cannot be queried, every candidate is
unmatched (→ queue). The extractor writing junk is the failure mode this module
exists to prevent; writing nothing is always the safer error.
"""
import logging
import re

logger = logging.getLogger(__name__)

_ARTICLE_RE = re.compile(r"^(the|los|las|el|la)\s+", re.IGNORECASE)
_EDGE_PUNCT_RE = re.compile(r"^[^\w]+|[^\w]+$")


def normalize(name: str) -> str:
    """Conservative canonical key: casefold, trim edge punctuation and one article."""
    value = " ".join(str(name).split())
    value = _ARTICLE_RE.sub("", value)
    value = _EDGE_PUNCT_RE.sub("", value)
    return value.casefold()


# ── Live catalogs (actors / malware) ─────────────────────────────────────────

def build_index(entities: list[dict]) -> dict[str, str]:
    """Map every normalized name and alias to the entity's canonical display name."""
    index: dict[str, str] = {}
    for entity in entities or []:
        canonical = (entity.get("name") or "").strip()
        if not canonical:
            continue
        keys = [canonical] + [a for a in (entity.get("aliases") or []) if a]
        for key in keys:
            index.setdefault(normalize(key), canonical)
    return index


def _fetch_catalog(list_fn, label: str) -> list[dict]:
    """Fetch id+name+aliases for a whole entity type. Fail-closed on any error."""
    try:
        return list_fn(getAll=True, customAttributes="id name aliases") or []
    except Exception as exc:
        logger.warning(
            "[resolver] %s catalog fetch failed (%s) — failing closed, all candidates queued",
            label, exc,
        )
        return []


def fetch_actor_index(client) -> dict[str, str]:
    return build_index(_fetch_catalog(client.intrusion_set.list, "intrusion-set"))


def fetch_malware_index(client) -> dict[str, str]:
    return build_index(_fetch_catalog(client.malware.list, "malware"))


def split_matches(names: list[str], index: dict[str, str]) -> tuple[list[str], list[str]]:
    """Partition candidates into (canonical resolved names, unmatched originals).

    Resolved values are the catalog's canonical display names, deduped in order.
    """
    resolved: list[str] = []
    unmatched: list[str] = []
    for name in names:
        canonical = index.get(normalize(name))
        if canonical:
            if canonical not in resolved:
                resolved.append(canonical)
        else:
            unmatched.append(name)
    return resolved, unmatched


# ── Sector taxonomy (fixed, canonical EN + EN/ES synonyms) ───────────────────

_SECTOR_TAXONOMY: dict[str, list[str]] = {
    "Finance": ["finance", "financial", "financial services", "banking", "banks", "banca",
                "finanzas", "fintech", "insurance", "seguros", "cryptocurrency"],
    "Government": ["government", "gobierno", "public sector", "sector publico",
                   "public administration", "municipalities", "embassies", "diplomatic"],
    "Defense": ["defense", "defence", "defensa", "military", "militar", "defense industry",
                "defense industrial base", "defense analysis"],
    "Healthcare": ["healthcare", "health", "salud", "sanidad", "hospitals", "hospital",
                   "medical", "public health"],
    "Energy": ["energy", "energia", "oil and gas", "oil", "gas", "petroleum", "electric",
               "electricity", "power", "nuclear", "renewables"],
    "Manufacturing": ["manufacturing", "manufactura", "industrial", "industria",
                      "sector industrial", "factories", "heavy industry"],
    "Technology": ["technology", "tecnologia", "it", "information technology", "software",
                   "tech", "saas", "cloud", "semiconductors", "it services"],
    "Telecommunications": ["telecommunications", "telecom", "telecomunicaciones",
                           "isp", "internet service providers", "mobile operators"],
    "Education": ["education", "educacion", "universities", "university", "academia",
                  "academic", "schools", "research institutions"],
    "Transportation": ["transportation", "transport", "transporte", "logistics",
                       "logistica", "aviation", "airlines", "railways", "shipping"],
    "Retail": ["retail", "minorista", "comercio", "e-commerce", "ecommerce",
               "consumer goods", "supermarkets", "wholesale trade", "wholesale"],
    "Media": ["media", "medios", "press", "prensa", "journalism", "news",
              "entertainment", "broadcasting"],
    "Legal": ["legal", "law firms", "law", "abogados", "juridico"],
    "Agriculture": ["agriculture", "agricultura", "farming", "food", "alimentos",
                    "food and agriculture"],
    "Construction": ["construction", "construccion", "engineering firms"],
    "Hospitality": ["hospitality", "hotels", "hoteles", "tourism", "turismo",
                    "restaurants", "gaming", "casinos"],
    "Mining": ["mining", "mineria", "metals", "extractives"],
    "Pharmaceutical": ["pharmaceutical", "pharma", "farmaceutica", "biotech",
                       "biotechnology", "life sciences"],
    "Aerospace": ["aerospace", "aeroespacial", "space", "satellites"],
    "Automotive": ["automotive", "automotriz", "car manufacturers"],
    "Maritime": ["maritime", "maritimo", "ports", "puertos", "naval",
                 "maritime logistics", "shipping companies"],
    "Water": ["water", "agua", "water utilities", "water and wastewater", "wastewater"],
    "Utilities": ["utilities", "servicios publicos", "critical utilities"],
    "Critical Infrastructure": ["critical infrastructure", "infraestructura critica"],
    "Nonprofit": ["nonprofit", "non-profit", "ngo", "ngos", "ong", "civil society",
                  "humanitarian", "think tanks", "religious movements",
                  "religious organizations"],
    "Research": ["research", "investigacion", "r&d", "laboratories", "national labs",
                 "policy research", "research institutes", "think tank"],
}

_SECTOR_INDEX: dict[str, str] = {}
for _canonical, _synonyms in _SECTOR_TAXONOMY.items():
    _SECTOR_INDEX[normalize(_canonical)] = _canonical
    for _syn in _synonyms:
        _SECTOR_INDEX.setdefault(normalize(_syn), _canonical)


def resolve_sector(name: str) -> str | None:
    return _SECTOR_INDEX.get(normalize(name))


# ── Country catalog (canonical EN + EN/ES synonyms and abbreviations) ────────

_COUNTRIES: dict[str, list[str]] = {
    "United States": ["us", "usa", "u.s.", "u.s.a.", "united states of america",
                      "estados unidos", "ee.uu.", "eeuu", "america"],
    "United Kingdom": ["uk", "u.k.", "great britain", "britain", "reino unido", "england"],
    "Russia": ["russian federation", "rusia"],
    "China": ["people's republic of china", "prc", "mainland china"],
    "North Korea": ["dprk", "democratic people's republic of korea", "corea del norte"],
    "South Korea": ["republic of korea", "rok", "korea", "corea del sur"],
    "Iran": ["islamic republic of iran", "irán"],
    "Germany": ["alemania", "deutschland"], "France": ["francia"],
    "Spain": ["espana", "españa"], "Italy": ["italia"], "Portugal": [],
    "Netherlands": ["holland", "paises bajos", "the netherlands"],
    "Belgium": ["belgica"], "Switzerland": ["suiza"], "Austria": [],
    "Poland": ["polonia"], "Ukraine": ["ucrania"], "Belarus": ["bielorrusia"],
    "Czech Republic": ["czechia", "republica checa"], "Slovakia": ["eslovaquia"],
    "Hungary": ["hungria"], "Romania": ["rumania"], "Bulgaria": [],
    "Greece": ["grecia"], "Turkey": ["turkiye", "turquia"],
    "Sweden": ["suecia"], "Norway": ["noruega"], "Denmark": ["dinamarca"],
    "Finland": ["finlandia"], "Iceland": ["islandia"], "Ireland": ["irlanda"],
    "Estonia": [], "Latvia": ["letonia"], "Lithuania": ["lituania"],
    "Serbia": [], "Croatia": ["croacia"], "Slovenia": ["eslovenia"],
    "Bosnia and Herzegovina": ["bosnia"], "Albania": [], "North Macedonia": ["macedonia"],
    "Moldova": [], "Georgia": [], "Armenia": [], "Azerbaijan": ["azerbaiyan"],
    "Kazakhstan": ["kazajistan"], "Uzbekistan": ["uzbekistan"],
    "Kyrgyzstan": ["kirguistan"], "Tajikistan": ["tayikistan"],
    "Turkmenistan": [], "Mongolia": [],
    "Japan": ["japon"], "Taiwan": ["republic of china"], "Hong Kong": [],
    "India": [], "Pakistan": ["pakistan"], "Bangladesh": [], "Sri Lanka": [],
    "Nepal": [], "Afghanistan": ["afganistan"], "Myanmar": ["burma"],
    "Thailand": ["tailandia"], "Vietnam": ["viet nam"], "Laos": [],
    "Cambodia": ["camboya"], "Malaysia": ["malasia"], "Singapore": ["singapur"],
    "Indonesia": [], "Philippines": ["filipinas"], "Brunei": [],
    "Australia": [], "New Zealand": ["nueva zelanda"],
    "Israel": [], "Palestine": ["palestinian territories", "palestina"],
    "Lebanon": ["libano"], "Syria": ["siria"], "Jordan": ["jordania"],
    "Iraq": ["irak"], "Saudi Arabia": ["arabia saudita", "arabia saudi", "ksa"],
    "United Arab Emirates": ["uae", "emiratos arabes unidos", "emirates"],
    "Qatar": ["catar"], "Kuwait": [], "Bahrain": ["barein"], "Oman": [],
    "Yemen": [], "Egypt": ["egipto"], "Libya": ["libia"], "Tunisia": ["tunez"],
    "Algeria": ["argelia"], "Morocco": ["marruecos"], "Sudan": ["sudan"],
    "Ethiopia": ["etiopia"], "Kenya": ["kenia"], "Somalia": [],
    "Nigeria": [], "Ghana": [], "Senegal": [], "Ivory Coast": ["cote d'ivoire"],
    "Cameroon": ["camerun"], "Democratic Republic of the Congo": ["drc", "congo"],
    "Uganda": [], "Tanzania": [], "Rwanda": ["ruanda"], "Mozambique": [],
    "Zimbabwe": [], "Zambia": [], "Angola": [], "Botswana": [], "Namibia": [],
    "South Africa": ["sudafrica"],
    "Mexico": ["méxico"], "Guatemala": [], "Honduras": [], "El Salvador": [],
    "Nicaragua": [], "Costa Rica": [], "Panama": ["panamá"],
    "Cuba": [], "Dominican Republic": ["republica dominicana"], "Haiti": ["haití"],
    "Jamaica": [], "Trinidad and Tobago": [],
    "Colombia": [], "Venezuela": [], "Ecuador": [], "Peru": ["perú", "republic of peru"],
    "Bolivia": [], "Chile": [], "Argentina": [], "Uruguay": [], "Paraguay": [],
    "Brazil": ["brasil"], "Guyana": [], "Suriname": [], "Canada": ["canadá"],
}

_COUNTRY_INDEX: dict[str, str] = {}
for _canonical, _synonyms in _COUNTRIES.items():
    _COUNTRY_INDEX[normalize(_canonical)] = _canonical
    for _syn in _synonyms:
        _COUNTRY_INDEX.setdefault(normalize(_syn), _canonical)


def resolve_country(name: str) -> str | None:
    return _COUNTRY_INDEX.get(normalize(name))


_COMPOUND_SPLIT_RE = re.compile(r"\s+and\s+|\s*,\s*|\s*/\s*", re.IGNORECASE)


def split_taxonomy_matches(names: list[str], resolver) -> tuple[list[str], list[str]]:
    """Partition against a fixed-taxonomy resolver (resolve_sector/resolve_country).

    Compound phrases the LLM emits as one value ("policy research and defense
    analysis") are decomposed on and/,// when the whole phrase has no match —
    matched parts resolve, unmatched parts queue individually.
    """
    resolved: list[str] = []
    unmatched: list[str] = []

    def _add(canonical):
        if canonical not in resolved:
            resolved.append(canonical)

    for name in names:
        canonical = resolver(name)
        if canonical:
            _add(canonical)
            continue
        parts = [p for p in _COMPOUND_SPLIT_RE.split(name) if p.strip()]
        if len(parts) > 1:
            part_hits = [(p, resolver(p)) for p in parts]
            if any(c for _, c in part_hits):
                for part, c in part_hits:
                    _add(c) if c else unmatched.append(part)
                continue
        unmatched.append(name)
    return resolved, unmatched
