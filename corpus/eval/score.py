#!/usr/bin/env python3
"""Corrector de concordancia: JSON intermedio vs STIX oficial parcial de CISA.

Las métricas P/R/F1 describen coincidencia con el anexo, no corrección factual
absoluta. Un elemento extraído que no figure en STIX requiere adjudicación
contra la prosa antes de llamarlo error. La validación de citas de este script
es diagnóstica: informa citas no localizadas, pero no filtra objetos.

Uso: python3 score.py <run.json> <referencia.stix.json> <texto_extraido.txt>

1. Valida el anclaje: cada quote (espacios plegados) debe ser subcadena del texto.
2. Empareja por tipo segun la regla 3.5 del eje 3 y reporta P/R/F1 por tipo.
   attack-pattern: por T-id exacto + segunda pasada a nivel de tecnica padre.
   relationship: tripleta (valor origen normalizado, tipo, valor destino normalizado);
   para la referencia STIX los extremos se resuelven siguiendo
   source_ref/target_ref.
"""
import json, re, sys, unicodedata
from collections import defaultdict

def fold(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()

def norm_value(v: str) -> str:
    v = v.strip().lower()
    v = v.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")
    if v.startswith("*."):
        v = v[2:]
    return v

def norm_name(v: str) -> str:
    v = unicodedata.normalize("NFKD", v.lower())
    return re.sub(r"[^a-z0-9]+", " ", v).strip()

TID_RE = re.compile(r"\[?(T\d{4}(?:\.\d{3})?)\]?")

def tid_of(name: str):
    m = TID_RE.search(name or "")
    return m.group(1) if m else None

def parent(tid: str) -> str:
    return tid.split(".")[0]

def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    denominator = 2 * tp + fp + fn
    f = 2 * tp / denominator if denominator else None
    return p, r, f

def fmt_metric(value):
    return "N/A" if value is None else f"{value:.2%}"

run = json.load(open(sys.argv[1]))
reference = json.load(open(sys.argv[2]))
text = fold(open(sys.argv[3]).read())

# ── 1. validacion de anclaje ─────────────────────────────────────────────────
bad_quotes = []
for kind, objs in (("ent", run["entities"]), ("rel", run["relationships"])):
    for o in objs:
        if fold(o["quote"]) not in text:
            label = o.get("value") or f"{o['source']}-{o['type']}-{o['target']}"
            bad_quotes.append((kind, label, o["quote"][:70]))
total_objs = len(run["entities"]) + len(run["relationships"])
localized = total_objs - len(bad_quotes)
citation_result = f"{localized}/{total_objs}" if total_objs else "N/A (0/0)"
print(f"── Citas localizadas: {citation_result} contra el texto")
for kind, label, q in bad_quotes:
    print(f"   ✗ {kind} {label}: “{q}…”")

# ── 2. preparar referencia oficial parcial ───────────────────────────────────
reference_objs = {o["id"]: o for o in reference["objects"]}
reference_sets: dict[str, set] = defaultdict(set)
for o in reference["objects"]:
    t = o["type"]
    if t == "indicator":
        m = re.search(r"=\s*'([^']+)'", o.get("pattern", ""))
        if m: reference_sets["indicator"].add(norm_value(m.group(1)))
    elif t == "attack-pattern":
        tid = tid_of(o.get("name", ""))
        if tid: reference_sets["attack-pattern"].add(tid)
    elif t in ("threat-actor", "malware", "vulnerability", "intrusion-set", "tool"):
        key = "threat-actor" if t == "intrusion-set" else t
        reference_sets[key].add(norm_name(o.get("name", "")))

def resolve_reference(ref):
    o = reference_objs.get(ref)
    if not o: return None
    if o["type"] == "indicator":
        m = re.search(r"=\s*'([^']+)'", o.get("pattern", ""))
        return norm_value(m.group(1)) if m else None
    return norm_name(o.get("name", ""))

reference_rels = set()
for o in reference["objects"]:
    if o["type"] == "relationship":
        s = resolve_reference(o.get("source_ref"))
        d = resolve_reference(o.get("target_ref"))
        if s and d: reference_rels.add((s, o.get("relationship_type"), d))

# ── 3. preparar extraccion ───────────────────────────────────────────────────
mine: dict[str, set] = defaultdict(set)
by_id = {}
for e in run["entities"]:
    by_id[e["id"]] = e
    t = e["type"]
    if t == "indicator":
        mine["indicator"].add(norm_value(e["value"]))
    elif t == "attack-pattern":
        tid = tid_of(e["value"])
        if tid: mine["attack-pattern"].add(tid)
    elif t in ("threat-actor", "malware", "vulnerability"):
        mine[t].add(norm_name(e["value"]))
    # sector/country/technology no existen en la referencia STIX de CISA:
    # se listan aparte

def endpoint(eid):
    e = by_id[eid]
    return norm_value(e["value"]) if e["type"] == "indicator" else norm_name(e["value"])

my_rels = {(endpoint(r["source"]), r["type"], endpoint(r["target"])) for r in run["relationships"]}

# ── 4. metricas por tipo ─────────────────────────────────────────────────────
print("\n── Métricas de concordancia contra el STIX oficial parcial")
print(
    f"{'tipo':<16} {'STIX':>4} {'extraído':>8} "
    f"{'TP_STIX':>7} {'FP_STIX':>7} {'FN_STIX':>7} "
    f"{'P_STIX':>7} {'R_STIX':>7} {'F1_STIX':>7}"
)
for t in ("indicator", "attack-pattern", "threat-actor", "malware", "vulnerability"):
    g, m = reference_sets[t], mine[t]
    tp = len(g & m); fp = len(m - g); fn = len(g - m)
    p, r, f = prf(tp, fp, fn)
    print(f"{t:<16} {len(g):>4} {len(m):>8} {tp:>7} {fp:>7} {fn:>7} "
          f"{fmt_metric(p):>7} {fmt_metric(r):>7} {fmt_metric(f):>7}")
    if fn: print(f"   FN_STIX ({t}): {sorted(g - m)}")
    if fp:
        print(f"   FP_STIX ({t}) — ausentes del anexo; adjudicar contra la prosa: "
              f"{sorted(m - g)}")

# attack-pattern a nivel padre
gp = {parent(x) for x in reference_sets["attack-pattern"]}
mp = {parent(x) for x in mine["attack-pattern"]}
tp = len(gp & mp); fp = len(mp - gp); fn = len(gp - mp)
p, r, f = prf(tp, fp, fn)
print(f"{'attack (padre)':<16} {len(gp):>4} {len(mp):>8} {tp:>7} {fp:>7} {fn:>7} "
      f"{fmt_metric(p):>7} {fmt_metric(r):>7} {fmt_metric(f):>7}")
if fn: print(f"   FN_STIX (padre): {sorted(gp - mp)}")

# relaciones
tp = len(reference_rels & my_rels)
fp = len(my_rels - reference_rels)
fn = len(reference_rels - my_rels)
p, r, f = prf(tp, fp, fn)
print(f"{'relationship':<16} {len(reference_rels):>4} {len(my_rels):>8} {tp:>7} {fp:>7} {fn:>7} "
      f"{fmt_metric(p):>7} {fmt_metric(r):>7} {fmt_metric(f):>7}")
if fn:
    print("   FN_STIX (rel):")
    for x in sorted(reference_rels - my_rels): print(f"      {x}")
if fp:
    print("   FP_STIX (rel) — ausentes del anexo; adjudicar contra la prosa:")
    for x in sorted(my_rels - reference_rels): print(f"      {x}")

# extraído fuera del vocabulario de la referencia STIX (decisión B: se juzga
# aparte y no castiga)
extra = [f"{e['type']}:{e['value']}" for e in run["entities"] if e["type"] in ("sector", "country", "technology")]
print(f"\n── Fuera del alcance de STIX (decisión B — revisar a mano, no castiga): {len(extra)}")
for x in extra: print(f"   {x}")
