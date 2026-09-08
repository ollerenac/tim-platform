"""Fase A/B regression tests — closed-world entity resolution + quarantine queue
(design 260724-fa).

Fixtures are the REAL junk entities from the 2026-07-22 audit: the resolver must
make each observed failure class impossible to write to the graph.
"""
import pytest

try:
    import entity_resolver
    import queue_store
    import queue_worker
    import opencti_client
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

_skip = pytest.mark.skipif(not _IMPORT_OK, reason="fase A modules not yet implemented")


@pytest.fixture
def tmp_queue(tmp_path, monkeypatch):
    """Point the shared SQLite at a temp file so queue writes are assertable."""
    import stats_store
    monkeypatch.setattr(stats_store, "DB_PATH", str(tmp_path / "stats.db"))
    return tmp_path


# ── Resolver: live-catalog matching ──────────────────────────────────────────

_CATALOG = [
    {"id": "is--hj", "name": "Homeland Justice", "aliases": []},
    {"id": "is--apt28", "name": "APT28", "aliases": ["Fancy Bear", "Sofacy"]},
    {"id": "is--tg", "name": "The Gentlemen", "aliases": []},
]


@_skip
def test_exact_and_casefold_match():
    index = entity_resolver.build_index(_CATALOG)
    resolved, unmatched = entity_resolver.split_matches(
        ["APT28", "homeland justice"], index
    )
    assert resolved == ["APT28", "Homeland Justice"]
    assert unmatched == []


@_skip
def test_alias_resolves_to_canonical_name():
    index = entity_resolver.build_index(_CATALOG)
    resolved, unmatched = entity_resolver.split_matches(["Fancy Bear"], index)
    assert resolved == ["APT28"]
    assert unmatched == []


@_skip
def test_truncated_fragment_never_matches_full_name():
    """Audit case: 'Land Justice' (fragment of Homeland Justice) must NOT resolve —
    conservative matching, no fuzzy."""
    index = entity_resolver.build_index(_CATALOG)
    resolved, unmatched = entity_resolver.split_matches(["Land Justice"], index)
    assert resolved == []
    assert unmatched == ["Land Justice"]


@_skip
def test_article_normalization_unifies_gentlemen():
    """Audit case: 'Gentlemen' (article-truncated 'The Gentlemen') resolves to the
    canonical card instead of creating a duplicate — the class P0.3 could not catch."""
    index = entity_resolver.build_index(_CATALOG)
    resolved, unmatched = entity_resolver.split_matches(["Gentlemen"], index)
    assert resolved == ["The Gentlemen"]
    assert unmatched == []


@_skip
def test_catalog_fetch_failure_fails_closed():
    """OpenCTI unreachable → empty index → everything unmatched (queued), nothing
    written. Writing junk is the failure mode this module exists to prevent."""
    class _Boom:
        def list(self, **kwargs):
            raise RuntimeError("opencti down")

    class _Client:
        intrusion_set = _Boom()

    index = entity_resolver.fetch_actor_index(_Client())
    assert index == {}


# ── Fixed taxonomies ─────────────────────────────────────────────────────────

@_skip
def test_sector_taxonomy_unifies_spanish_and_english():
    """Audit case: 94 free-form sectors (Manufactura vs Manufacturing, Banca...)."""
    assert entity_resolver.resolve_sector("Manufactura") == "Manufacturing"
    assert entity_resolver.resolve_sector("manufacturing") == "Manufacturing"
    assert entity_resolver.resolve_sector("Banca") == "Finance"
    assert entity_resolver.resolve_sector("Law Firms") == "Legal"
    assert entity_resolver.resolve_sector("water") == "Water"
    # Audit's hyperspecific junk sector goes to the queue, not the graph.
    assert entity_resolver.resolve_sector("Religious Movements Banned In China") is None


@_skip
def test_compound_sector_phrases_decompose():
    """Quick-win (medición 260724): frases compuestas emitidas como un solo valor
    se descomponen — partes con match resuelven, partes sin match encolan solas."""
    resolved, unmatched = entity_resolver.split_taxonomy_matches(
        ["policy research and defense analysis", "maritime logistics",
         "quantum blockchain and healthcare"],
        entity_resolver.resolve_sector,
    )
    assert resolved == ["Research", "Defense", "Maritime", "Healthcare"]
    assert unmatched == ["quantum blockchain"]


@_skip
def test_country_catalog_canonicalizes_variants():
    assert entity_resolver.resolve_country("US") == "United States"
    assert entity_resolver.resolve_country("EE.UU.") == "United States"
    assert entity_resolver.resolve_country("Perú") == "Peru"
    assert entity_resolver.resolve_country("Atlantis") is None  # → queue


# ── Queue store ──────────────────────────────────────────────────────────────

@_skip
def test_queue_enqueue_and_dedup(tmp_queue):
    payload = {"candidate": "UNC9999", "resolved_sectors": ["Finance"]}
    queue_store.enqueue("actor", "UNC9999", payload, "https://blog.example/post")
    queue_store.enqueue("actor", "UNC9999", payload, "https://blog.example/post")  # dup
    entries = queue_store.list_entries("pending")
    assert len(entries) == 1
    assert entries[0]["candidate_name"] == "UNC9999"
    assert entries[0]["claim_payload"]["resolved_sectors"] == ["Finance"]


# ── End-to-end: closed world at the write seam ───────────────────────────────

@_skip
def test_unknown_actor_is_quarantined_not_created(mock_pycti, tmp_queue):
    """The audit's core failure: an uncataloged candidate ('CobaltSt…', 'unknown
    Chinese-speaking APT group') must produce ZERO intrusion_set.create calls and
    ONE queue row each — linked claims survive for later approval/re-match."""
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    mock_pycti.identity.create.return_value = {"id": "identity--finance"}

    result = opencti_client.create_targeting_relationships(
        client=mock_pycti,
        threat_actor_names=["CobaltSt…", "unknown Chinese-speaking APT group"],
        sector_names=["banca"],
        source_url="https://blog.example/apt-report",
        observed_at="2026-07-24T00:00:00+00:00",
    )

    mock_pycti.intrusion_set.create.assert_not_called()
    # No actor resolved → sector axis cannot produce a relationship either.
    mock_pycti.stix_core_relationship.create.assert_not_called()
    assert result["object_ids"] == []

    queued = queue_store.list_entries("pending")
    names = sorted(e["candidate_name"] for e in queued)
    assert names == ["CobaltSt…", "unknown Chinese-speaking APT group"]
    assert all(e["claim_payload"]["resolved_sectors"] == ["Finance"] for e in queued)


@_skip
def test_known_actor_links_with_canonical_name(mock_pycti, tmp_queue):
    """A cataloged actor mentioned by alias writes under its CANONICAL name —
    guaranteed upsert onto the existing card, never a new entity."""
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    mock_pycti.intrusion_set.list.return_value = [
        {"id": "is--apt28", "name": "APT28", "aliases": ["Fancy Bear"]},
    ]
    mock_pycti.intrusion_set.create.return_value = {"id": "is--apt28"}
    mock_pycti.identity.create.return_value = {"id": "identity--finance"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "rel--x"}

    opencti_client.create_targeting_relationships(
        client=mock_pycti,
        threat_actor_names=["Fancy Bear"],
        sector_names=["Finance"],
        source_url="https://blog.example/apt-report",
        observed_at="2026-07-24T00:00:00+00:00",
    )

    assert mock_pycti.intrusion_set.create.call_args.kwargs["name"] == "APT28"
    assert queue_store.list_entries("pending") == []


# ── Fase B: queue lifecycle ──────────────────────────────────────────────────

def _quarantine_one(mock_pycti, tmp_queue, candidate="UNC9999"):
    """Run one real ingest that quarantines `candidate`; returns its queue row."""
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    opencti_client.create_targeting_relationships(
        client=mock_pycti,
        threat_actor_names=[candidate],
        sector_names=["Finance"],
        source_url="https://blog.example/original-report",
        observed_at="2026-07-24T00:00:00+00:00",
    )
    return queue_store.list_entries("pending")[0]


@_skip
def test_approve_creates_entity_and_replays_claim(mock_pycti, tmp_queue):
    """Approve = create the actor + replay the deferred claim through the same
    closed-world seam, with the ORIGINAL document's provenance."""
    entry = _quarantine_one(mock_pycti, tmp_queue)

    # After approval-create, the catalog contains the candidate → replay resolves.
    mock_pycti.intrusion_set.list.return_value = [
        {"id": "is--unc9999", "name": "UNC9999", "aliases": []},
    ]
    mock_pycti.intrusion_set.create.return_value = {"id": "is--unc9999"}
    mock_pycti.identity.create.return_value = {"id": "identity--finance"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "rel--unc-fin"}

    result = queue_worker.approve_entry(entry["id"], client=mock_pycti)

    assert result["entity_id"] == "is--unc9999"
    rel = mock_pycti.stix_core_relationship.create.call_args.kwargs
    assert rel["fromId"] == "is--unc9999" and rel["toId"] == "identity--finance"
    row = queue_store.get_entry(entry["id"])
    assert row["status"] == "approved"
    assert row["resolved_entity_id"] == "is--unc9999"
    assert queue_store.list_entries("pending") == []


@_skip
def test_reject_marks_entry_without_touching_graph(mock_pycti, tmp_queue):
    entry = _quarantine_one(mock_pycti, tmp_queue, candidate="unknown APT group")
    mock_pycti.intrusion_set.create.reset_mock()

    queue_worker.reject_entry(entry["id"])

    mock_pycti.intrusion_set.create.assert_not_called()
    assert queue_store.get_entry(entry["id"])["status"] == "rejected"
    with pytest.raises(ValueError):  # double transition blocked
        queue_worker.reject_entry(entry["id"])


@_skip
def test_rematch_resolves_retroactively_when_connector_catalogs_actor(mock_pycti, tmp_queue):
    """The 'MITRE catalogs it six months later' scenario: the hourly job replays
    the claim automatically; the non-matching entry stays pending."""
    entry = _quarantine_one(mock_pycti, tmp_queue)
    _quarantine_one(mock_pycti, tmp_queue, candidate="StillUnknownActor")

    # Connector later imports UNC9999 (alias match included).
    mock_pycti.intrusion_set.list.return_value = [
        {"id": "is--unc9999", "name": "UNC9999", "aliases": ["TEMP.9999"]},
    ]
    mock_pycti.intrusion_set.create.return_value = {"id": "is--unc9999"}
    mock_pycti.identity.create.return_value = {"id": "identity--finance"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "rel--retro"}

    summary = queue_worker.rematch_pending(client=mock_pycti)

    assert summary == {"pending": 2, "auto_matched": 1}
    assert queue_store.get_entry(entry["id"])["status"] == "auto_matched"
    remaining = queue_store.list_entries("pending")
    assert [e["candidate_name"] for e in remaining] == ["StillUnknownActor"]
    # Retroactive relationship carries the original document's provenance.
    assert mock_pycti.external_reference.create.call_args.kwargs["url"] == (
        "https://blog.example/original-report"
    )


@_skip
def test_approve_sector_refused_taxonomy_is_code(mock_pycti, tmp_queue):
    """An unmatched sector is a taxonomy gap — approving it as a one-off entity
    would leave future ingests still unresolvable."""
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    mock_pycti.intrusion_set.create.return_value = {"id": "is--example"}
    opencti_client.create_targeting_relationships(
        client=mock_pycti,
        threat_actor_names=["Example Actor"],
        sector_names=["Quantum Blockchain Sector"],
        source_url="https://blog.example/report",
        observed_at="2026-07-24T00:00:00+00:00",
    )
    entry = queue_store.list_entries("pending")[0]
    assert entry["category"] == "sector"

    with pytest.raises(ValueError, match="taxonomy"):
        queue_worker.approve_entry(entry["id"], client=mock_pycti)
    assert queue_store.get_entry(entry["id"])["status"] == "pending"
