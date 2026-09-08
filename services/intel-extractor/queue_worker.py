"""
queue_worker.py — Fase B actions on the entity quarantine queue.

Three exits per queued candidate (design 260724-fa):
  approve  — the analyst confirms it's real: create the entity, then replay the
             deferred claim through the SAME closed-world write seam.
  re-match — a curated connector cataloged it later: the hourly job replays the
             claim automatically; relationships appear retroactively with the
             ORIGINAL document's provenance.
  reject   — noise; dies without ever touching the graph.

Replay always goes through create_targeting_relationships: by replay time the
candidate resolves against the catalog, so the normal seam creates the
relationships — one write path, no bypass around the closed world.
"""
import logging
from datetime import datetime, timezone

import entity_resolver
import queue_store

logger = logging.getLogger(__name__)

_APPROVABLE = {"actor", "malware"}


def _replay_claim(client, entry: dict) -> dict:
    import opencti_client  # local import — opencti_client imports queue_store

    payload = entry.get("claim_payload") or {}
    category = entry["category"]
    candidate = entry["candidate_name"]
    actors = list(payload.get("resolved_actors") or [])
    malware = list(payload.get("resolved_malware") or [])
    sectors = list(payload.get("resolved_sectors") or [])
    countries = list(payload.get("resolved_countries") or [])
    if category == "actor" and candidate not in actors:
        actors.append(candidate)
    elif category == "malware" and candidate not in malware:
        malware.append(candidate)
    elif category == "sector" and candidate not in sectors:
        sectors.append(candidate)
    elif category == "country" and candidate not in countries:
        countries.append(candidate)

    return opencti_client.create_targeting_relationships(
        client=client,
        threat_actor_names=actors,
        sector_names=sectors,
        source_url=entry["source_url"],
        observed_at=payload.get("observed_at")
        or datetime.now(timezone.utc).isoformat(),
        malware_names=malware,
        country_names=countries,
        cve_ids=list(payload.get("cve_ids") or []),
    )


def approve_entry(entry_id: int, client=None) -> dict:
    """Analyst-approved candidate: create the entity, replay the claim, mark row.

    Only actor/malware are approvable — an unmatched sector/country means a
    TAXONOMY gap; the honest fix is extending entity_resolver's taxonomy (code),
    not a one-off entity that future ingests still can't resolve.
    """
    entry = queue_store.get_entry(entry_id)
    if entry is None:
        raise KeyError(f"queue entry {entry_id} not found")
    if entry["status"] != "pending":
        raise ValueError(f"entry {entry_id} is {entry['status']}, not pending")
    if entry["category"] not in _APPROVABLE:
        raise ValueError(
            f"{entry['category']} candidates are approved by extending the "
            "taxonomy in entity_resolver.py, not via this endpoint"
        )

    if client is None:
        from opencti_client import build_pycti_client
        client = build_pycti_client()

    candidate = entry["candidate_name"]
    if entry["category"] == "actor":
        created = client.intrusion_set.create(name=candidate, update=True)
    else:
        created = client.malware.create(name=candidate, is_family=True, update=True)
    entity_id = (created or {}).get("id")
    if not entity_id:
        raise RuntimeError(f"entity creation returned no id for {candidate!r}")

    result = _replay_claim(client, entry)
    queue_store.mark(entry_id, "approved", resolved_entity_id=entity_id)
    logger.info("[queue] approved %r (%s) → %s, %d objects written",
                candidate, entry["category"], entity_id, len(result["object_ids"]))
    return {"entity_id": entity_id, "object_ids": result["object_ids"]}


def reject_entry(entry_id: int) -> None:
    entry = queue_store.get_entry(entry_id)
    if entry is None:
        raise KeyError(f"queue entry {entry_id} not found")
    if entry["status"] != "pending":
        raise ValueError(f"entry {entry_id} is {entry['status']}, not pending")
    queue_store.mark(entry_id, "rejected")
    logger.info("[queue] rejected %r (%s)", entry["candidate_name"], entry["category"])


def rematch_pending(client=None) -> dict:
    """Hourly re-match: replay claims whose candidate the catalog now contains.

    Answers "MITRE catalogs the actor six months later" — the graph completes
    itself retroactively, provenance intact. Cheap when the queue is empty.
    """
    pending = queue_store.list_entries("pending", limit=1000)
    if not pending:
        return {"pending": 0, "auto_matched": 0}

    if client is None:
        from opencti_client import build_pycti_client
        client = build_pycti_client()

    indexes = {
        "actor": entity_resolver.fetch_actor_index(client)
        if any(e["category"] == "actor" for e in pending) else {},
        "malware": entity_resolver.fetch_malware_index(client)
        if any(e["category"] == "malware" for e in pending) else {},
    }

    matched = 0
    for entry in pending:
        category = entry["category"]
        candidate = entry["candidate_name"]
        if category in indexes:
            canonical = indexes[category].get(entity_resolver.normalize(candidate))
        elif category == "sector":
            canonical = entity_resolver.resolve_sector(candidate)
        else:
            canonical = entity_resolver.resolve_country(candidate)
        if not canonical:
            continue
        try:
            _replay_claim(client, entry)
            queue_store.mark(entry["id"], "auto_matched")
            matched += 1
            logger.info("[queue] auto-matched %r (%s) → %r retroactively",
                        candidate, category, canonical)
        except Exception as exc:
            logger.warning("[queue] re-match replay failed for %r: %s", candidate, exc)

    return {"pending": len(pending), "auto_matched": matched}
