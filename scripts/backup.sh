#!/usr/bin/env bash
# backup.sh — full data backup for the opencti-7-pilot stack (P1.1, audit 2026-07-22).
#
# What it captures:
#   1. Elasticsearch: consistent snapshot via the ES snapshot API (fs repo /backups,
#      wired in docker-compose as the esbackups volume + path.repo). Tarring the live
#      esdata volume is NOT safe — this project already lived through ES corruption.
#   2. Every other stateful named volume, tarred read-only via busybox.
#
# Deliberately excluded:
#   - esdata (covered by the API snapshot; raw tar of a live ES dir is inconsistent)
#
# Restore (ES): start stack, then
#   docker exec <es> curl -s -X POST 'localhost:9200/_snapshot/backup_repo/<snap>/_restore'
# Restore (volume): docker run --rm -v <proj>_<vol>:/data -v <dir>:/backup busybox \
#   sh -c 'cd /data && tar xzf /backup/<vol>.tar.gz'
set -euo pipefail

PROJECT="${PROJECT:-opencti-7-pilot}"
ES_CONTAINER="${ES_CONTAINER:-${PROJECT}-elasticsearch-1}"
BACKUP_DIR="${BACKUP_DIR:-./backups/$(date +%Y%m%d-%H%M%S)}"
VOLUMES=(redisdata rabbitmqdata miniodata briefingsdata extractordata)

mkdir -p "$BACKUP_DIR"
echo "==> Backup to $BACKUP_DIR (project: $PROJECT)"
failures=0

# ── 1. Elasticsearch snapshot (in-container curl: ES has no host port) ───────
es_curl() { docker exec "$ES_CONTAINER" curl -s "$@"; }

echo "--> ES snapshot..."
if es_curl -f "http://localhost:9200/_cluster/health" > /dev/null; then
  # Idempotent repo registration; fails hard if path.repo is missing from compose.
  if ! es_curl -X PUT "http://localhost:9200/_snapshot/backup_repo" \
      -H 'Content-Type: application/json' \
      -d '{"type":"fs","settings":{"location":"/backups"}}' | grep -q '"acknowledged":true'; then
    echo "    ERROR: snapshot repo not registered (is path.repo=/backups in compose?)"
    failures=$((failures + 1))
  else
    snap="snap-$(date +%Y%m%d-%H%M%S)"
    es_curl -X PUT \
      "http://localhost:9200/_snapshot/backup_repo/${snap}?wait_for_completion=true" \
      > "$BACKUP_DIR/es-snapshot.json"
    state=$(grep -o '"state":"[A-Z]*"' "$BACKUP_DIR/es-snapshot.json" | head -1)
    if [ "$state" = '"state":"SUCCESS"' ]; then
      echo "    ES snapshot $snap: SUCCESS"
    else
      echo "    ERROR: ES snapshot state=$state (see $BACKUP_DIR/es-snapshot.json)"
      failures=$((failures + 1))
    fi
  fi
else
  echo "    ERROR: Elasticsearch unreachable in container $ES_CONTAINER"
  failures=$((failures + 1))
fi

# ── 2. Named volumes (read-only tar; esbackups last so it includes the snapshot) ──
for vol in "${VOLUMES[@]}" esbackups; do
  full_vol="${PROJECT}_${vol}"
  if ! docker volume inspect "$full_vol" > /dev/null 2>&1; then
    echo "--> Volume $full_vol: MISSING"
    failures=$((failures + 1))
    continue
  fi
  echo "--> Volume $full_vol..."
  if docker run --rm \
      -v "${full_vol}:/data:ro" \
      -v "$(realpath "$BACKUP_DIR"):/backup" \
      busybox tar czf "/backup/${vol}.tar.gz" -C /data .; then
    echo "    $vol → ${vol}.tar.gz ($(du -h "$BACKUP_DIR/${vol}.tar.gz" | cut -f1))"
  else
    echo "    ERROR: $vol tar failed"
    failures=$((failures + 1))
  fi
done

echo "==> Contents:"
ls -lh "$BACKUP_DIR"
if [ "$failures" -gt 0 ]; then
  echo "==> BACKUP INCOMPLETE: $failures failure(s)" >&2
  exit 1
fi
echo "==> Backup complete: $BACKUP_DIR"
