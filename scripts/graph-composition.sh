#!/usr/bin/env bash
# Read-only snapshot of the knowledge graph: entity classes, relationship types
# and connectivity rate per class. Prints a dated cut; writes nothing.
#
# Usage: ./scripts/graph-composition.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")"

es() {
  docker compose --profile core exec -T elasticsearch \
    curl -fsS -H 'Content-Type: application/json' "http://localhost:9200/$1" -d "$2"
}

printf 'graph-composition cut: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '== entity classes (stix_domain_objects) ==\n'
es 'opencti_stix_domain_objects-*/_search' \
  '{"size":0,"aggs":{"t":{"terms":{"field":"entity_type.keyword","size":40}}}}' \
  | jq -r '.aggregations.t.buckets[] | "\(.key)\t\(.doc_count)"' \
  | awk -F'\t' '{printf "  %-22s %10d\n",$1,$2; s+=$2} END {printf "  %-22s %10d\n","TOTAL",s}'

printf '\n== observables / core / meta ==\n'
for idx in stix_cyber_observables stix_core_relationships stix_meta_relationships; do
  n=$(docker compose --profile core exec -T elasticsearch \
        curl -fsS "http://localhost:9200/opencti_${idx}-*/_count" | jq -r .count)
  printf '  %-30s %10d\n' "$idx" "$n"
done

printf '\n== core relationship types ==\n'
es 'opencti_stix_core_relationships-*/_search' \
  '{"size":0,"aggs":{"r":{"terms":{"field":"relationship_type.keyword","size":30}}}}' \
  | jq -r '.aggregations.r.buckets[] | "\(.key)\t\(.doc_count)"' \
  | awk -F'\t' '{printf "  %-22s %10d\n",$1,$2; s+=$2} END {printf "  %-22s %10d\n","TOTAL",s}'

# Connectivity: unique entities of each class appearing as an endpoint of at
# least one core relationship. `connections` is nested, so cardinality on the
# endpoint id is the count of distinct wired entities.
# ponytail: cardinality is approximate above the precision threshold; 40000 is
# well above every class measured here except indicator, whose rate is reported
# as such and not as an exact count.
printf '\n== connectivity: entities wired by class ==\n'
es 'opencti_stix_core_relationships-*/_search' \
  '{"size":0,"aggs":{"n":{"nested":{"path":"connections"},"aggs":{"t":{"terms":{"field":"connections.types.keyword","size":40},"aggs":{"u":{"cardinality":{"field":"connections.internal_id.keyword","precision_threshold":40000}}}}}}}}' \
  | jq -r '.aggregations.n.t.buckets[] | "\(.key)\t\(.u.value)"' \
  | awk -F'\t' '$2>20 {printf "  %-22s %10d\n",$1,$2}'
