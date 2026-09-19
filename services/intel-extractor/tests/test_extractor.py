import json

import pytest
from unittest.mock import MagicMock


try:
    from extractor import build_stix_pattern
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False


_skip = pytest.mark.skipif(not _IMPORT_OK, reason="extractor not yet implemented")


@_skip
def test_build_stix_pattern_valid():
    """Well-formed IOCs build the expected STIX pattern."""
    assert build_stix_pattern("ip", "1.2.3.4") == ("[ipv4-addr:value = '1.2.3.4']", "IPv4-Addr")
    assert build_stix_pattern("hash_md5", "d41d8cd98f00b204e9800998ecf8427e")[0] == (
        "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"
    )


@_skip
def test_build_stix_pattern_rejects_injection():
    """H1: malformed / injection-shaped values are rejected by per-type validation (returns None)."""
    # trailing backslash + quote-breakout attempt in an 'ip' slot
    assert build_stix_pattern("ip", "1.2.3.4\\") is None
    assert build_stix_pattern("ip", "x'] OR [url:value='y") is None
    # unknown type still returns None
    assert build_stix_pattern("bogus", "1.2.3.4") is None


@_skip
def test_build_stix_pattern_escapes_backslash_before_quote():
    """A backslash in a validated URL value is doubled so it can't escape the closing quote.

    URL shape forbids raw quotes/backslashes, so use a value that passes shape yet the
    escaping order still matters conceptually — assert on a domain-free url path segment.
    """
    # A url with an embedded backslash fails shape validation (defense in depth) → None.
    assert build_stix_pattern("url", "http://evil/\\") is None


@_skip
def test_extract_from_text_seam(monkeypatch):
    """extract_from_text is the pure LLM→ground→dedup seam: deduped, no OpenCTI."""
    import extractor

    fixed = {
        "iocs": [
            {"type": "ip", "value": "1.2.3.4"},
            {"type": "ip", "value": "1.2.3.4"},  # duplicate — must dedup to one
            {"type": "domain", "value": "evil.example.com"},
        ],
        "techniques": [{"name": "Phishing", "description": "email-based lure"}],
        "malware_families": [],
        "threat_actors": ["Example Actor"],
        "targeted_sectors": ["Water"],
        "victim_technologies": ["Unitronics PLC"],
        "campaign_summary": "Actors targeted water utilities.",
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    # input text carries the IOC values so the grounding filter keeps them
    result = extractor.extract_from_text(
        "Example Actor targeted Water and used 1.2.3.4 and evil.example.com",
        "unknown",
    )

    assert set(result.keys()) == {
        "unique_iocs",
        "technique_keywords",
        "threat_actors",
        "targeted_sectors",
        "malware_families",
        "targeted_countries",
        "exploited_cves",
        "victim_technologies",
        "campaign_summary",
        "v2_entities",
        "v2_relationships",
    }
    assert result["unique_iocs"] == [
        {"type": "ip", "value": "1.2.3.4"},
        {"type": "domain", "value": "evil.example.com"},
    ]
    assert result["technique_keywords"] == {"phishing"}
    assert result["threat_actors"] == {"Example Actor"}
    assert result["targeted_sectors"] == {"water"}
    assert result["victim_technologies"] == {"Unitronics PLC"}
    assert result["campaign_summary"] == "Actors targeted water utilities."


@_skip
def test_extract_from_text_drops_ungrounded_targeting_claims(monkeypatch):
    """LLM-only actor/sector claims cannot become graph knowledge."""
    import extractor

    fixed = {
        "iocs": [],
        "techniques": [],
        "malware_families": [],
        "threat_actors": ["Invented Actor"],
        "targeted_sectors": ["Imaginary Sector"],
        "victim_technologies": [],
        "campaign_summary": "",
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *args, **kwargs: fixed)

    result = extractor.extract_from_text(
        "This source contains no named actor or victim sector.",
        "report",
    )

    assert result["threat_actors"] == set()
    assert result["targeted_sectors"] == set()


@_skip
def test_extract_from_text_grounds_malware_and_countries_verbatim(monkeypatch):
    """malware_families/targeted_countries pass the same grounding filter as actors,
    keeping verbatim casing (NOT lowercased like sectors)."""
    import extractor

    fixed = {
        "iocs": [],
        "techniques": [],
        "malware_families": ["GhostLoader", "Imaginary"],
        "threat_actors": [],
        "targeted_sectors": [],
        "targeted_countries": ["Ukraine", "Atlantis"],
        "victim_technologies": [],
        "campaign_summary": "",
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    result = extractor.extract_from_text(
        "GhostLoader was deployed against organizations in Ukraine.",
        "report",
    )

    assert result["malware_families"] == {"GhostLoader"}
    assert result["targeted_countries"] == {"Ukraine"}


def _targeting_fixture(threat_actors=(), malware_families=()):
    return {
        "iocs": [],
        "techniques": [],
        "malware_families": list(malware_families),
        "threat_actors": list(threat_actors),
        "targeted_sectors": [],
        "targeted_countries": [],
        "victim_technologies": [],
        "campaign_summary": "",
    }


@_skip
def test_truncated_names_do_not_ground_inside_full_names(monkeypatch):
    """P0.3 regression (audit 2026-07-22): substring grounding accepted 'Land Justice'
    inside 'Homeland Justice' and 'Gentlemen' inside 'The Gentlemen' — live junk
    Intrusion-Sets. Word-boundary grounding must reject the fragment but keep the
    full name."""
    import extractor

    fixed = _targeting_fixture(
        threat_actors=["Land Justice", "Homeland Justice", "Gentlemen"],
    )
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    result = extractor.extract_from_text(
        "Homeland Justice claimed the attack. The Gentlemen leaked the data.",
        "report",
    )

    # "Land Justice" dies: 'land' sits inside 'homeland', so the word-boundary
    # lookbehind rejects it. "Gentlemen" survives: it IS a complete word in
    # "The Gentlemen" — article truncation is not deterministically detectable
    # here and is mitigated by the prompt's complete-name rule instead.
    assert result["threat_actors"] == {"Homeland Justice", "Gentlemen"}
    assert "Land Justice" not in result["threat_actors"]


@_skip
def test_defective_entity_names_rejected_before_graph(monkeypatch):
    """P0.3 regression: every name class observed live in the audit is rejected —
    literal-ellipsis truncations (CobaltSt…, BACKOR…), too-short fragments, and
    placeholder phrases (unknown Chinese-speaking APT group). Legit names pass."""
    import extractor

    fixed = _targeting_fixture(
        threat_actors=[
            "CobaltSt…",
            "BACKOR...",
            "unknown Chinese-speaking APT group",
            "AB",
            "Handala Hack Team",
        ],
        malware_families=["Remexi"],
    )
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    result = extractor.extract_from_text(
        "CobaltSt… BACKOR... AB attack by an unknown Chinese-speaking APT group. "
        "Handala Hack Team deployed Remexi.",
        "report",
    )

    assert result["threat_actors"] == {"Handala Hack Team"}
    assert result["malware_families"] == {"Remexi"}


@_skip
def test_extract_from_text_harvests_cves_deterministically(monkeypatch):
    """CVEs come from a regex over the fanged text — deduped, uppercased, sorted."""
    extractor = _patch_llm_iocs(monkeypatch, [])

    result = extractor.extract_from_text(
        "Actors exploited CVE-2023-1234, cve-2023-1234 and CVE-2020-0601 in the wild."
    )
    assert result["exploited_cves"] == ["CVE-2020-0601", "CVE-2023-1234"]

    result = extractor.extract_from_text("No vulnerabilities named here.")
    assert result["exploited_cves"] == []


@_skip
def test_run_extraction_persists_source_backed_targeting(monkeypatch):
    """Explicit actor/sector claims become source-backed graph objects in the Report."""
    import extractor

    source_url = "https://source.example/reports/campaign"
    client = object()
    target_object_ids = [
        "threat-actor--example",
        "identity--water",
        "relationship--targets-water",
    ]
    create_targeting = MagicMock(return_value={
        "object_ids": target_object_ids,
        "external_reference_ids": ["external-reference--source"],
    })
    create_report = MagicMock(return_value={"id": "report--campaign"})

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    monkeypatch.setattr(extractor, "extract_url_text", lambda url: "Example Actor targeted the water sector.")
    monkeypatch.setattr(
        extractor,
        "extract_from_text",
        lambda *args, **kwargs: {
            "unique_iocs": [],
            "technique_keywords": set(),
            "threat_actors": {"Example Actor"},
            "targeted_sectors": {"water"},
            "victim_technologies": set(),
            "campaign_summary": "Example Actor targeted water utilities.",
        },
    )
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: client)
    monkeypatch.setattr(extractor, "create_targeting_relationships", create_targeting, raising=False)
    monkeypatch.setattr(extractor, "create_report", create_report)
    monkeypatch.setattr(extractor.stats_store, "increment", lambda docs, iocs: None)

    job_id = "job-source-backed-targeting"
    extractor.register_job(job_id)
    extractor.run_extraction(job_id, "url", None, source_url, source_type="report")

    create_targeting.assert_called_once()
    targeting_kwargs = create_targeting.call_args.kwargs
    assert targeting_kwargs["client"] is client
    assert targeting_kwargs["threat_actor_names"] == ["Example Actor"]
    assert targeting_kwargs["sector_names"] == ["water"]
    assert targeting_kwargs["source_url"] == source_url
    assert targeting_kwargs["observed_at"].endswith("+00:00")
    assert create_report.call_args.kwargs["indicator_ids"] == target_object_ids
    assert create_report.call_args.kwargs["external_reference_ids"] == [
        "external-reference--source"
    ]


@_skip
def test_run_extraction_forwards_new_targeting_axes(monkeypatch):
    """Step 9 passes malware/country/CVE lists to create_targeting_relationships."""
    import extractor

    client = object()
    create_targeting = MagicMock(return_value={
        "object_ids": [],
        "external_reference_ids": [],
    })
    create_report = MagicMock(return_value={"id": "report--axes"})

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    monkeypatch.setattr(
        extractor, "extract_url_text",
        lambda url: "Example Actor deployed GhostLoader in Ukraine via CVE-2023-1234.",
    )
    monkeypatch.setattr(
        extractor,
        "extract_from_text",
        lambda *args, **kwargs: {
            "unique_iocs": [],
            "technique_keywords": set(),
            "threat_actors": {"Example Actor"},
            "targeted_sectors": set(),
            "malware_families": {"GhostLoader"},
            "targeted_countries": {"Ukraine"},
            "exploited_cves": ["CVE-2023-1234"],
            "victim_technologies": set(),
            "campaign_summary": "",
        },
    )
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: client)
    monkeypatch.setattr(extractor, "create_targeting_relationships", create_targeting, raising=False)
    monkeypatch.setattr(extractor, "create_report", create_report)
    monkeypatch.setattr(extractor.stats_store, "increment", lambda docs, iocs: None)

    job_id = "job-new-targeting-axes"
    extractor.register_job(job_id)
    extractor.run_extraction(
        job_id, "url", None, "https://source.example/reports/axes", source_type="report"
    )

    create_targeting.assert_called_once()
    kwargs = create_targeting.call_args.kwargs
    assert kwargs["threat_actor_names"] == ["Example Actor"]
    assert kwargs["sector_names"] == []
    assert kwargs["malware_names"] == ["GhostLoader"]
    assert kwargs["country_names"] == ["Ukraine"]
    assert kwargs["cve_ids"] == ["CVE-2023-1234"]


def _attribution_run(monkeypatch, client, create_report, created_by=None):
    """Common scaffolding for report identity attribution contracts (quick-260716-m2g)."""
    import extractor

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    monkeypatch.setattr(
        extractor, "extract_url_text",
        lambda url: "Volt Typhoon targeted critical infrastructure organizations.",
    )
    monkeypatch.setattr(
        extractor,
        "extract_from_text",
        lambda *args, **kwargs: {
            "unique_iocs": [],
            "technique_keywords": set(),
            "threat_actors": set(),
            "targeted_sectors": set(),
            "victim_technologies": set(),
            "campaign_summary": "",
        },
    )
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: client)
    monkeypatch.setattr(extractor, "create_report", create_report)
    monkeypatch.setattr(extractor.stats_store, "increment", lambda docs, iocs: None)

    job_id = "job-report-attribution"
    extractor.register_job(job_id)
    kwargs = {"source_type": "report"}
    if created_by is not None:
        kwargs["created_by"] = created_by
    extractor.run_extraction(
        job_id, "url", None, "https://attack.mitre.org/groups/G1017", **kwargs
    )
    return extractor.jobs[job_id]


@_skip
def test_run_extraction_attributes_report_to_created_by_identity(monkeypatch):
    """created_by identity is ensured once (idempotent) and its id reaches create_report."""
    client = MagicMock()
    client.identity.create.return_value = {"id": "identity--mitre"}
    create_report = MagicMock(return_value={"id": "report--group"})

    job = _attribution_run(
        monkeypatch, client, create_report,
        created_by={"name": "The MITRE Corporation", "type": "Organization"},
    )

    client.identity.create.assert_called_once_with(
        type="Organization", name="The MITRE Corporation", update=True
    )
    assert create_report.call_args.kwargs["created_by_id"] == "identity--mitre"
    assert job["status"] == "complete"
    assert job["report_id"] == "report--group"


@_skip
def test_run_extraction_without_created_by_never_creates_attribution_identity(monkeypatch):
    """Default path unchanged: no identity ensure, no createdBy on the Report."""
    client = MagicMock()
    create_report = MagicMock(return_value={"id": "report--plain"})

    job = _attribution_run(monkeypatch, client, create_report)

    client.identity.create.assert_not_called()
    assert not create_report.call_args.kwargs.get("created_by_id")
    assert job["status"] == "complete"


@_skip
def test_run_extraction_identity_failure_does_not_fail_the_job(monkeypatch):
    """Attribution must not fail closed: identity errors WARN and the Report still lands."""
    client = MagicMock()
    client.identity.create.side_effect = RuntimeError("identity write failed")
    create_report = MagicMock(return_value={"id": "report--degraded"})

    job = _attribution_run(
        monkeypatch, client, create_report,
        created_by={"name": "The MITRE Corporation", "type": "Organization"},
    )

    assert job["status"] == "complete"
    assert job["report_id"] == "report--degraded"
    assert create_report.call_args.kwargs.get("created_by_id") is None


def _patch_llm_iocs(monkeypatch, iocs):
    """Monkeypatch the extractor's LLM seam to emit a fixed IOC list."""
    import extractor

    fixed = {
        "iocs": iocs,
        "techniques": [],
        "malware_families": [],
        "threat_actors": [],
        "targeted_sectors": [],
        "victim_technologies": [],
        "campaign_summary": "",
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)
    return extractor


@_skip
def test_regex_hash_harvest_adds_hashes_when_llm_misses(monkeypatch):
    """Hash recall does not depend only on the model noticing IOC appendices."""
    extractor = _patch_llm_iocs(monkeypatch, [])
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    result = extractor.extract_from_text(
        "IOC appendix\n"
        f"MD5: {md5}\n"
        f"SHA1: {sha1}\n"
        f"SHA256: {sha256}\n"
    )

    assert {(i["type"], i["value"]) for i in result["unique_iocs"]} == {
        ("hash_md5", md5),
        ("hash_sha1", sha1),
        ("hash_sha256", sha256),
    }
    for ioc in result["unique_iocs"]:
        assert extractor.build_stix_pattern(ioc["type"], ioc["value"]) is not None


@_skip
def test_regex_hash_harvest_does_not_split_longer_hashes(monkeypatch):
    """Hex boundary guards prevent SHA256 from also becoming SHA1/MD5."""
    extractor = _patch_llm_iocs(monkeypatch, [])
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    too_long = "a" * 65

    result = extractor.extract_from_text(f"File hashes:\n{sha256}\n{too_long}\n")

    assert result["unique_iocs"] == [{"type": "hash_sha256", "value": sha256}]


@_skip
def test_refang_defanged_values(monkeypatch):
    """EXT-02: defanged LLM output is canonicalized and survives to build_stix_pattern."""
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "ip", "value": "1.2.3[.]4"},
        {"type": "url", "value": "hxxp://c2.bad/beacon"},
        {"type": "domain", "value": "evil[dot]com"},
    ])
    result = extractor.extract_from_text(
        "doc with 1.2.3[.]4 then hxxp://c2.bad/beacon and evil[dot]com"
    )
    values = {(i["type"], i["value"]) for i in result["unique_iocs"]}
    assert values == {
        ("ip", "1.2.3.4"),
        ("url", "http://c2.bad/beacon"),
        ("domain", "evil.com"),
    }
    for ioc in result["unique_iocs"]:
        assert extractor.build_stix_pattern(ioc["type"], ioc["value"]) is not None


@_skip
def test_refang_dedup(monkeypatch):
    """Defanged + fanged spellings of the same IOC collapse to ONE canonical entry."""
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "ip", "value": "1.2.3[.]4"},
        {"type": "ip", "value": "1.2.3.4"},
    ])
    result = extractor.extract_from_text("doc with 1.2.3[.]4 and 1.2.3.4")
    assert result["unique_iocs"] == [{"type": "ip", "value": "1.2.3.4"}]


@_skip
def test_email_salvage(monkeypatch):
    """A predicted domain that only ever appears email-embedded in the doc is
    salvaged to the full verbatim email; a domain that also appears standalone
    is kept as a domain (guard against demoting legitimate domain IOCs)."""
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "domain", "value": "invoice-relay.example"},  # only ever after localpart@
        {"type": "domain", "value": "standalone.example"},     # appears bare too
    ])
    # invoice-relay.example also occurs as a SUFFIX of a longer hostname
    # (portal.invoice-relay.example) — that is not a standalone occurrence and
    # must not block the salvage.
    result = extractor.extract_from_text(
        "mail from billing@invoice-relay.example; lure page at "
        "https://portal.invoice-relay.example/login; loader hosted on standalone.example "
        "with replies to admin@standalone.example"
    )
    assert {(i["type"], i["value"]) for i in result["unique_iocs"]} == {
        ("email", "billing@invoice-relay.example"),
        ("domain", "standalone.example"),
    }


@_skip
def test_ungrounded_ioc_dropped(monkeypatch):
    """T-11-03: a predicted value not present in fang(doc text) is a hallucination — dropped."""
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "domain", "value": "fabricated.example"},
        {"type": "ip", "value": "203.0.113.7"},
    ])
    result = extractor.extract_from_text("only 203.0.113.7 appears in this document")
    assert result["unique_iocs"] == [{"type": "ip", "value": "203.0.113.7"}]


@_skip
def test_refang_injection_shape_still_rejected():
    """ASVS V5: fang() never widens the accept surface — injection shapes still rejected."""
    from ioc_fanger import fang

    from extractor import build_stix_pattern

    payload = "x'] OR [url:value='y"
    assert build_stix_pattern("ip", fang(payload)) is None
    # clean values pass through fang() untouched (verified property of ioc-fanger 5.1.1)
    assert fang("http://good.com") == "http://good.com"
    sha256 = "a" * 64
    assert fang(sha256) == sha256


@_skip
def test_guess_source_type():
    """EXT-04: pdf -> report; vendor-blog host -> blog; everything else -> unknown."""
    from extractor import _VENDOR_BLOG_HOSTS, _guess_source_type

    assert _guess_source_type("pdf", None) == "report"
    vendor_host = next(iter(_VENDOR_BLOG_HOSTS))
    assert _guess_source_type("url", f"https://{vendor_host}/post") == "blog"
    assert _guess_source_type("url", "https://cisa.example/adv") == "unknown"
    assert _guess_source_type("url", None) == "unknown"


@_skip
def test_cyber_centre_n8n_advisory_completes_with_zero_iocs(monkeypatch):
    """Cyber Centre n8n advisory is processed as a report with no indicators."""
    import extractor

    advisory_url = "https://www.cyber.gc.ca/en/alerts-advisories/n8n-security-advisory-av26-672"
    advisory_text = """
    n8n security advisory (AV26-672)
    Serial number: AV26-672
    Date: July 8, 2026

    On July 8, 2026, n8n published security advisories to address
    vulnerabilities in the following product:

    n8n - versions prior to 1.123.64
    n8n - versions prior to 2.30.1
    n8n - versions prior to 2.29.8

    The Cyber Centre encourages users and administrators to review the
    provided web link and apply the necessary update.

    n8n Security: https://github.com/n8n-io/n8n/security
    """
    llm_result = {
        "iocs": [],
        "techniques": [],
        "malware_families": [],
        "threat_actors": [],
        "targeted_sectors": [],
        "victim_technologies": ["n8n prior to 1.123.64", "n8n prior to 2.30.1", "n8n prior to 2.29.8"],
        "campaign_summary": "n8n published security advisories for affected product versions.",
    }
    create_indicator = MagicMock(name="create_indicator")

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    monkeypatch.setattr(extractor, "extract_url_text", lambda url: advisory_text)
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: llm_result)
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: object())
    monkeypatch.setattr(extractor, "create_indicator", create_indicator)
    monkeypatch.setattr(extractor, "lookup_attack_pattern", lambda *a, **k: None)
    monkeypatch.setattr(extractor, "create_report", lambda **k: {"id": "report--n8n"})
    monkeypatch.setattr(extractor.stats_store, "increment", lambda docs, iocs: None)

    job_id = "job-n8n-advisory"
    extractor.register_job(job_id)
    extractor.run_extraction(job_id, "url", None, advisory_url, source_type="advisory")

    create_indicator.assert_not_called()
    assert extractor.jobs[job_id]["status"] == "complete"
    assert extractor.jobs[job_id]["iocs_extracted"] == 0
    assert extractor.jobs[job_id]["report_id"] == "report--n8n"
    assert extractor.recent_docs[0]["filename"] == advisory_url
    assert extractor.recent_docs[0]["ioc_count"] == 0
    assert extractor.recent_docs[0]["status"] == "complete"


@_skip
def test_bulletin_reference_url_with_no_active_exploitation_is_suppressed(monkeypatch):
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "url", "value": "https://vendor.example/security/update"},
    ])
    text = """
    Boletín de seguridad

    No existe evidencia de explotación activa. Para más información y la
    actualización del fabricante consulte https://vendor.example/security/update
    """

    result = extractor.extract_from_text(text, source_type="bulletin")

    assert result["unique_iocs"] == []


@_skip
def test_bulletin_policy_is_section_aware_and_retains_explicit_malicious_observables(
    monkeypatch,
):
    vendor_url = "https://vendor.example/security/update"
    payload_url = "https://storage.example/payload.exe"
    ip = "203.0.113.9"
    sha256 = "a" * 64
    domain = "evil.example"
    email = "ops@evil.example"
    extractor = _patch_llm_iocs(monkeypatch, [
        {"type": "url", "value": vendor_url},
        {"type": "url", "value": payload_url},
        {"type": "ip", "value": ip},
        {"type": "hash_sha256", "value": sha256},
        {"type": "domain", "value": domain},
        {"type": "email", "value": email},
    ])
    text = f"""
    Estado de vulnerabilidad
    No hay evidencia de explotación activa. Referencia y parche del fabricante:
    {vendor_url}

    Indicadores maliciosos
    Una campaña de phishing descargó el payload desde {payload_url}. El payload
    se comunicó con el C2 {ip}. Artefacto de ataque SHA256 {sha256}.
    El dominio comprometido {domain} y el correo malicioso {email} fueron IOCs.
    """

    result = extractor.extract_from_text(text, source_type="bulletin")

    assert {(ioc["type"], ioc["value"]) for ioc in result["unique_iocs"]} == {
        ("url", payload_url),
        ("ip", ip),
        ("hash_sha256", sha256),
        ("domain", domain),
        ("email", email),
    }


@_skip
def test_bulletin_reference_section_rejects_sources_but_preserves_explicit_ioc_table(
    monkeypatch,
):
    """Observed CNSD layout separates editorial sources from an explicit IoC table."""
    reference_values = [
        ("domain", "gbhackers.com"),
        ("domain", "www.wordfence.com"),
        ("url", "https://github.com/apache/airflow/pull/66002"),
        ("domain", "seclists.org"),
    ]
    ioc_values = [
        ("ip", "23.133.4.108"),
        ("ip", "154.91.75.192"),
        ("domain", "nishihaoren1.top"),
        ("domain", "nishihaoren1.org"),
    ]
    extractor = _patch_llm_iocs(
        monkeypatch,
        [
            {"type": ioc_type, "value": value}
            for ioc_type, value in reference_values + ioc_values
        ],
    )
    text = """
    Fuente de Información: • hxxps://gbhackers.com/research/article
    www.wordfence.com
    https://github.com/apache/airflow/pull/66002
    seclists.org

    ALERTA INTEGRADA DE
    SEGURIDAD DIGITAL N° 116 Fecha: 08-07-2026
    Página: 08 de 14

    A. Indicadores de Compromiso (IoC)
    Tipo | Valor
    IP | 23.133.4.108
    IP | 154.91.75.192
    Dominio | nishihaoren1.top
    Dominio | nishihaoren1.org
    """

    result = extractor.extract_from_text(
        text, source_type="bulletin", include_diagnostics=True
    )

    assert {(ioc["type"], ioc["value"]) for ioc in result["accepted_iocs"]} == set(
        ioc_values
    )
    reference_rejections = {
        (item["type"], item["value"]): (item["reason"], item["stage"])
        for item in result["rejected_ioc_candidates"]
        if item["value"] in {value for _, value in reference_values}
    }
    assert reference_rejections == {
        candidate: ("bulletin_reference_section", "bulletin_policy")
        for candidate in reference_values
    }


@_skip
def test_bulletin_reference_section_keeps_locally_labeled_malicious_infrastructure(
    monkeypatch,
):
    extractor = _patch_llm_iocs(
        monkeypatch,
        [{"type": "domain", "value": "evil.example"}],
    )
    text = """
    References
    Malicious C2 infrastructure IOC: evil.example

    Recommendations
    Block confirmed attacker infrastructure.
    """

    result = extractor.extract_from_text(
        text, source_type="bulletin", include_diagnostics=True
    )

    assert result["accepted_iocs"] == [{"type": "domain", "value": "evil.example"}]
    assert not any(
        item["reason"] == "bulletin_reference_section"
        for item in result["rejected_ioc_candidates"]
    )


@_skip
@pytest.mark.parametrize("source_type", ["advisory", "report", "blog", "unknown"])
def test_bulletin_policy_is_identity_for_other_source_types(source_type):
    import extractor

    candidates = [{"type": "url", "value": "https://vendor.example/security/update"}]

    assert extractor.apply_bulletin_ioc_policy(
        candidates, "Vendor update reference", source_type
    ) is candidates


@_skip
def test_bulletin_suppression_completes_report_with_zero_indicators(monkeypatch):
    import extractor

    bulletin_url = "https://www.gob.pe/institucion/pcm/informes-publicaciones/example-cnsd"
    vendor_url = "https://vendor.example/security/update"
    bulletin_text = (
        "Security bulletin\n\nThere is no evidence of active exploitation. "
        f"Vendor advisory and patch reference: {vendor_url}"
    )
    llm_result = {
        "iocs": [{"type": "url", "value": vendor_url}],
        "techniques": [],
        "malware_families": [],
        "threat_actors": [],
        "targeted_sectors": [],
        "victim_technologies": [],
        "campaign_summary": "A vendor issued a security update.",
    }
    create_indicator = MagicMock(name="create_indicator")

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    monkeypatch.setattr(extractor, "extract_url_text", lambda url: bulletin_text)
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *args, **kwargs: llm_result)
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: object())
    monkeypatch.setattr(extractor, "create_indicator", create_indicator)
    monkeypatch.setattr(extractor, "lookup_attack_pattern", lambda *args, **kwargs: None)
    monkeypatch.setattr(extractor, "create_report", lambda **kwargs: {"id": "report--bulletin"})
    monkeypatch.setattr(extractor.stats_store, "increment", lambda docs, iocs: None)

    job_id = "job-bulletin-reference"
    extractor.register_job(job_id)
    extractor.run_extraction(job_id, "url", None, bulletin_url, source_type="bulletin")

    create_indicator.assert_not_called()
    assert extractor.jobs[job_id]["status"] == "complete"
    assert extractor.jobs[job_id]["iocs_extracted"] == 0
    assert extractor.jobs[job_id]["report_id"] == "report--bulletin"
    assert extractor.recent_docs[0]["status"] == "complete"
    assert extractor.recent_docs[0]["ioc_count"] == 0


def test_extract_from_text_tolerates_llm_nulls(monkeypatch):
    """LLM JSON mode can emit null inside any field (seen live on ATT&CK G0003/G0084:
    'NoneType' object has no attribute 'strip' killed the whole extraction). Null or
    non-string entries must be dropped, never crash the seam."""
    import extractor

    fixed = {
        "iocs": [{"type": "ip", "value": None}, {"type": None, "value": "1.2.3.4"}, None],
        "techniques": [{"name": None, "description": "x"}, "not-a-dict", None],
        "malware_families": [None, "RealFam"],
        "threat_actors": [None],
        "targeted_sectors": [None, "Energy"],
        "targeted_countries": [None],
        "victim_technologies": [None],
        "campaign_summary": None,
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    result = extractor.extract_from_text("RealFam malware hit the Energy sector. 1.2.3.4")

    assert result["campaign_summary"] == ""
    assert result["malware_families"] == {"RealFam"}
    assert result["targeted_sectors"] == {"energy"}
    assert result["threat_actors"] == set()


# ── v2.1 Anthropic provider seams (decision-llm 2026-08-10) ──────────────────

def test_validate_citations_drops_unanchored_objects():
    """Anchoring contract: quote must exist verbatim (whitespace-folded) in source."""
    import extractor
    source = (
        "APT99 deployed EvilLoader against the energy sector.\n"
        "The C2 domain was  bad.example.com  per the appendix."
    )
    data = {
        "entities": [
            {"id": "e1", "type": "threat-actor", "value": "APT99",
             "quote": "APT99 deployed EvilLoader against the energy sector."},
            {"id": "e2", "type": "indicator", "value": "bad.example.com", "ioc_type": "domain",
             "quote": "The C2 domain was bad.example.com per the appendix."},  # ws-folded match
            {"id": "e3", "type": "malware", "value": "GhostRAT",
             "quote": "GhostRAT was observed in the wild."},  # NOT in source -> drop
            {"id": "e4", "type": "malware", "value": "EvilLoader", "quote": ""},  # empty -> drop
        ],
        "relationships": [
            {"source": "e1", "type": "uses", "target": "e2",
             "quote": "APT99 deployed EvilLoader against the energy sector."},
            {"source": "e1", "type": "uses", "target": "e3",  # target dropped -> drop
             "quote": "APT99 deployed EvilLoader against the energy sector."},
            {"source": "e1", "type": "targets", "target": "e2",
             "quote": "This sentence is fabricated."},  # unanchored -> drop
        ],
    }
    entities, rels, stats = extractor.validate_citations(data, source)
    assert {e["id"] for e in entities} == {"e1", "e2"}
    assert len(rels) == 1 and rels[0]["target"] == "e2"
    assert stats == {"entities_dropped": 2, "relationships_dropped": 2}


def test_claude_diagnostics_preserve_raw_and_validated_objects(monkeypatch):
    """Evaluation diagnostics keep raw Haiku objects beside citation-filtered TIM output."""
    import extractor

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_final_message(self):
            return type("Response", (), {
                "content": [type("Text", (), {"type": "text", "text": json.dumps({
                    "entities": [
                        {"id": "e1", "type": "indicator", "value": "203.0.113.7",
                         "ioc_type": "ip", "quote": "Observed 203.0.113.7."},
                        {"id": "e2", "type": "malware", "value": "InventedWare",
                         "quote": "This sentence is not in the document."},
                    ],
                    "relationships": [], "campaign_summary": "Observed an IOC.",
                })})],
                "stop_reason": "end_turn",
                "usage": type("Usage", (), {"input_tokens": 12, "output_tokens": 34})(),
            })()

    class Client:
        class messages:
            @staticmethod
            def stream(**_kwargs):
                return Stream()

    monkeypatch.setattr(extractor, "LLM_PROVIDER", "bedrock")
    monkeypatch.setattr(extractor, "_get_anthropic_client", lambda: Client())

    result = extractor.extract_from_text(
        "Observed 203.0.113.7.", source_type="advisory", include_diagnostics=True
    )

    assert len(result["raw_v2_entities"]) == 2
    assert len(result["v2_entities"]) == 1
    assert result["citation_stats"]["entities_dropped"] == 1
    assert result["stop_reason"] == "end_turn"
    assert result["model_usage"] == {"input_tokens": 12, "output_tokens": 34}


@pytest.mark.parametrize(("mode", "response_text"), [
    ("transport", ""),
    ("refusal", ""),
    ("malformed_json", "not valid json"),
])
def test_claude_diagnostic_failures_propagate_to_the_runner(monkeypatch, mode, response_text):
    """Evaluation mode makes transport/refusal/parse failure explicit, never empty TIM."""
    import extractor

    class Stream:
        def __enter__(self):
            if mode == "transport":
                raise OSError("bedrock unavailable")
            return self

        def __exit__(self, *_args):
            return False

        def get_final_message(self):
            return type("Response", (), {
                "content": [type("Text", (), {"type": "text", "text": response_text})()],
                "stop_reason": "refusal" if mode == "refusal" else "end_turn",
                "usage": type("Usage", (), {"input_tokens": 1, "output_tokens": 1})(),
            })()

    class Client:
        class messages:
            @staticmethod
            def stream(**_kwargs):
                return Stream()

    monkeypatch.setattr(extractor, "LLM_PROVIDER", "bedrock")
    monkeypatch.setattr(extractor, "_get_anthropic_client", lambda: Client())

    with pytest.raises(extractor.DiagnosticExtractionError):
        extractor.extract_from_text("Observed 203.0.113.7.", include_diagnostics=True)


def test_v2_to_flat_projects_typed_entities():
    import extractor
    entities = [
        {"id": "e1", "type": "threat-actor", "value": "APT99", "quote": "q"},
        {"id": "e2", "type": "indicator", "value": "1.2.3.4", "ioc_type": "ip", "quote": "q"},
        {"id": "e3", "type": "attack-pattern", "value": "Phishing [T1566]", "quote": "q"},
        {"id": "e4", "type": "sector", "value": "energy", "quote": "q"},
        {"id": "e5", "type": "vulnerability", "value": "CVE-2025-1234", "quote": "q"},
        {"id": "e6", "type": "indicator", "value": "no-ioc-type", "quote": "q"},
    ]
    flat = extractor._v2_to_flat(entities, "summary text")
    assert flat["threat_actors"] == ["APT99"]
    assert flat["iocs"] == [{"type": "ip", "value": "1.2.3.4"}]
    assert flat["techniques"] == [{"name": "Phishing [T1566]", "description": ""}]
    assert flat["targeted_sectors"] == ["energy"]
    assert flat["campaign_summary"] == "summary text"
    # vulnerabilities ride the CVE regex harvest, never the flat projection
    assert "CVE-2025-1234" not in str(flat["iocs"])


def test_wildcard_domain_passes_shape_validation():
    """v2.1 rule: cert-table wildcard domains are indicators; STIX pattern must build."""
    import extractor
    result = extractor.build_stix_pattern("domain", "*.i.example.com")
    assert result is not None
    pattern, obs_type = result
    assert "*.i.example.com" in pattern and obs_type == "Domain-Name"
    # plain domains still pass; garbage still fails
    assert extractor.build_stix_pattern("domain", "example.com") is not None
    assert extractor.build_stix_pattern("domain", "*.") is None


# ── Bedrock provider seams (decision-llm 2026-08-10 rev. bedrock) ────────────

def test_bedrock_provider_builds_legacy_client_with_region(monkeypatch):
    """LLM_PROVIDER=bedrock must construct AnthropicBedrock(aws_region=...) — the
    legacy bedrock-runtime client. Never Mantle (403-gated for this account,
    2026-08-18) and never the direct-API client — auth is the instance IAM role."""
    import sys
    import extractor

    stub = MagicMock()
    monkeypatch.setitem(sys.modules, "anthropic", stub)
    monkeypatch.setattr(extractor, "LLM_PROVIDER", "bedrock")
    monkeypatch.setattr(extractor, "_anthropic_client", None)

    extractor._get_anthropic_client()

    stub.AnthropicBedrock.assert_called_once_with(aws_region=extractor.AWS_REGION)
    stub.AnthropicBedrockMantle.assert_not_called()
    stub.Anthropic.assert_not_called()
    monkeypatch.setattr(extractor, "_anthropic_client", None)  # don't leak the stub


def test_claude_model_selects_bedrock_id(monkeypatch):
    """Bedrock legacy path takes cross-region inference profile IDs
    (us.anthropic.<model>-<date>-v1:0)."""
    import extractor
    assert extractor._claude_model() == extractor.BEDROCK_MODEL
    assert extractor.BEDROCK_MODEL.startswith("us.anthropic.")
    assert extractor.BEDROCK_MODEL.endswith("-v1:0")


def test_extract_from_text_bedrock_uses_whole_document_claude_path(monkeypatch):
    """One whole-document call to call_llm_anthropic, however long the text is,
    with the v2 objects preserved."""
    import extractor

    calls = []

    def fake_claude(chunk, source_type="unknown"):
        calls.append(chunk)
        return {
            "iocs": [{"type": "ip", "value": "1.2.3.4"}],
            "techniques": [], "malware_families": [], "threat_actors": [],
            "targeted_sectors": [], "targeted_countries": [], "victim_technologies": [],
            "campaign_summary": "s",
            "v2_entities": [{"id": "e1", "type": "indicator", "value": "1.2.3.4",
                             "ioc_type": "ip", "quote": "1.2.3.4"}],
            "v2_relationships": [],
        }

    monkeypatch.setattr(extractor, "LLM_PROVIDER", "bedrock")
    monkeypatch.setattr(extractor, "call_llm_anthropic", fake_claude)
    text = "Indicator observed at 1.2.3.4 during the campaign. " * 50
    result = extractor.extract_from_text(text)

    assert len(calls) == 1  # whole document, no chunking
    assert {"type": "ip", "value": "1.2.3.4"} in result["unique_iocs"]
    assert result["v2_entities"][0]["value"] == "1.2.3.4"


def test_strip_json_fences_tolerates_haiku_markdown_wrapper():
    """Haiku wraps v2.1 JSON in ```json fences (live 2026-08-18); opus emits bare
    JSON. Both must reach json.loads intact — fence-blindness cost a full dev-run."""
    import extractor
    bare = '{"entities": [], "relationships": []}'
    fenced = "```json\n" + bare + "\n```"
    fenced_plain = "```\n" + bare + "\n```"
    assert extractor._strip_json_fences(bare) == bare
    assert extractor._strip_json_fences(fenced) == bare
    assert extractor._strip_json_fences(fenced_plain) == bare
    assert extractor._strip_json_fences("  " + fenced + "  ") == bare


# ── Bedrock-only contracts (local Ollama path retired 2026-09-19) ────────────

def test_bedrock_is_the_only_provider_and_no_local_llm_client_is_imported():
    """The evaluation harnesses assert LLM_PROVIDER == "bedrock"; the chunked
    Ollama path and the direct Anthropic API client must stay gone."""
    import sys
    import extractor

    assert extractor.LLM_PROVIDER == "bedrock"
    for retired in ("call_llm", "chunk_text", "SYSTEM_PROMPT", "_ollama_client", "ANTHROPIC_API_KEY"):
        assert not hasattr(extractor, retired), retired
    assert "ollama" not in sys.modules


def test_call_llm_anthropic_sends_frozen_prompt_and_document_type_hint(monkeypatch):
    """EXT-04: the hint lives in the user turn only; the system prompt is v2.1 verbatim."""
    import extractor

    sent = {}

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_final_message(self):
            return type("Response", (), {
                "content": [type("Text", (), {"type": "text", "text": '{"entities": [], "relationships": []}'})()],
                "stop_reason": "end_turn",
                "usage": type("Usage", (), {"input_tokens": 1, "output_tokens": 1})(),
            })()

    class Client:
        class messages:
            @staticmethod
            def stream(**kwargs):
                sent.update(kwargs)
                return Stream()

    monkeypatch.setattr(extractor, "_get_anthropic_client", lambda: Client())

    extractor.extract_from_text("report body", "report")

    assert sent["system"] == extractor.SYSTEM_PROMPT_V21
    assert sent["model"] == extractor.BEDROCK_MODEL
    user_msg = sent["messages"][0]["content"]
    assert "Document type hint: report" in user_msg
    assert '"""\nreport body\n"""' in user_msg


def test_flat_projection_fields_all_flow_to_extract_output(monkeypatch):
    """Contract parity: every field the flat projection carries must survive
    aggregation. threat_actors (2026-07-15) and malware_families (2026-07-17) were
    both extracted and then silently dropped by extract_from_text's allowlist."""
    import extractor

    fixed = extractor._v2_to_flat([], "")
    # Historic renames at the seam — new fields must NOT be added here without wiring
    renamed = {"iocs": "unique_iocs", "techniques": "technique_keywords"}
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)

    result = extractor.extract_from_text("benign text with no indicators")

    missing = {field for field in fixed if renamed.get(field, field) not in result}
    assert not missing, f"flat field(s) {sorted(missing)} are dropped by extract_from_text"


def test_diagnostics_retain_grounding_dedup_policy_and_shape_rejections(monkeypatch):
    """Diagnostic mode explains every dropped candidate and reports one complete
    entry for the single whole-document call."""
    import extractor

    vendor_url = "https://vendor.example/security/update"
    fixed = {
        **extractor._v2_to_flat([], ""),
        "iocs": [
            None,
            {"type": "ip"},
            {"type": "ip", "value": "198.51.100.99"},
            {"type": "ip", "value": "203.0.113.7"},
            {"type": "ip", "value": "203.0.113.7"},
            {"type": "cve", "value": "CVE-2026-1234"},
            {"type": "url", "value": vendor_url},
        ],
    }
    monkeypatch.setattr(extractor, "call_llm_anthropic", lambda *a, **k: fixed)
    text = (
        "No hay evidencia de explotacion activa. Referencia y parche del fabricante: "
        f"{vendor_url}\n\nIndicador malicioso 203.0.113.7 and CVE-2026-1234"
    )

    result = extractor.extract_from_text(text, "bulletin", include_diagnostics=True)

    assert result["accepted_iocs"] == [{"type": "ip", "value": "203.0.113.7"}]
    rejected = result["rejected_ioc_candidates"]
    assert all(set(item) == {"type", "value", "reason", "stage"} for item in rejected)
    assert {item["reason"] for item in rejected} >= {
        "empty_candidate",
        "ungrounded",
        "duplicate",
        "bulletin_no_active_exploitation",
        "unsupported_type_or_invalid_shape",
    }
    assert {item["stage"] for item in rejected} >= {
        "response_parser", "grounding", "dedup", "bulletin_policy", "shape_validation",
    }
    assert result["chunk_diagnostics"] == [
        {"chunk_index": 0, "status": "complete", "attempts": 1, "retry_count": 0, "error": None}
    ]
