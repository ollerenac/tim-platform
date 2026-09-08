import pytest
from unittest.mock import MagicMock, call

try:
    import indexer
    from indexer import build_embed_text
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

_skip = pytest.mark.skipif(not _IMPORT_OK, reason="indexer not yet implemented")


@_skip
def test_build_embed_text_with_description():
    # D-01: em dash format when description present, labels appended
    ind = {
        "x_opencti_main_observable_type": "IPv4-Addr",
        "name": "1.2.3.4",
        "description": "C2 server",
        "objectLabel": [{"value": "botnet-cc"}],
    }
    assert build_embed_text(ind) == "IPv4-Addr: 1.2.3.4 — C2 server botnet-cc"


@_skip
def test_build_embed_text_no_description():
    # D-03: bracket format when no description
    ind = {
        "x_opencti_main_observable_type": "IPv4-Addr",
        "name": "1.2.3.4",
        "description": None,
        "objectLabel": [{"value": "malware-distribution"}],
    }
    assert build_embed_text(ind) == "IPv4-Addr: 1.2.3.4 [malware-distribution]"


@_skip
def test_build_embed_text_no_description_no_labels():
    # D-03: empty bracket when no description and no labels
    ind = {
        "x_opencti_main_observable_type": "IPv4-Addr",
        "name": "1.2.3.4",
        "description": None,
        "objectLabel": [],
    }
    assert build_embed_text(ind) == "IPv4-Addr: 1.2.3.4 []"


@_skip
def test_build_embed_text_empty_labels_ignored():
    # D-01: no trailing space when labels empty but description present
    ind = {
        "x_opencti_main_observable_type": "IPv4-Addr",
        "name": "1.2.3.4",
        "description": "Ransomware C2",
        "objectLabel": [],
    }
    assert build_embed_text(ind) == "IPv4-Addr: 1.2.3.4 — Ransomware C2"


def _indicator(number):
    return {
        "id": f"indicator--{number}",
        "name": f"192.0.2.{number}",
        "x_opencti_main_observable_type": "IPv4-Addr",
        "description": "C2 server",
        "objectLabel": [{"value": "malware"}],
        "updated_at": f"2026-07-13T10:00:0{number}.000Z",
    }


@_skip
def test_index_batch_embeds_and_upserts_bounded_chunks(monkeypatch):
    collection = MagicMock()
    ollama_client = MagicMock()

    def embed(*, model, input, keep_alive):
        return MagicMock(embeddings=[[float(position)] * 768 for position, _ in enumerate(input)])

    ollama_client.embed.side_effect = embed
    monkeypatch.setattr(indexer, "_ollama", ollama_client)
    monkeypatch.setattr(indexer, "EMBED_BATCH_SIZE", 2)

    indexed = indexer._index_batch(collection, [_indicator(1), _indicator(2), _indicator(3)])

    assert indexed == 3
    assert ollama_client.embed.call_count == 2
    assert [len(item.kwargs["input"]) for item in ollama_client.embed.call_args_list] == [2, 1]
    assert collection.upsert.call_count == 2
    assert [len(item.kwargs["ids"]) for item in collection.upsert.call_args_list] == [2, 1]


@_skip
def test_run_index_cycle_resumes_checkpoint_and_promotes_final_watermark(monkeypatch):
    collection = MagicMock()
    collection.count.return_value = 101
    checkpoint = {
        "last_indexed_at": "",
        "scan_mode": "full",
        "scan_upper_bound": "2026-07-13T10:00:00.000Z",
        "scan_after": "cursor-1",
        "scan_processed": 100,
    }
    pages = [
        {
            "entities": [_indicator(1)],
            "pagination": {
                "endCursor": "cursor-2",
                "hasNextPage": True,
                "globalCount": 102,
            },
        },
        {
            "entities": [_indicator(2)],
            "pagination": {
                "endCursor": "cursor-3",
                "hasNextPage": False,
                "globalCount": 102,
            },
        },
    ]
    iterator_calls = []
    checkpoint_writes = []

    def iter_pages(client, **kwargs):
        iterator_calls.append(kwargs)
        yield from pages

    monkeypatch.setattr(indexer, "build_pycti_client", lambda: object())
    monkeypatch.setattr(indexer, "get_collection", lambda: collection)
    monkeypatch.setattr(indexer, "read_checkpoint", lambda value: checkpoint)
    monkeypatch.setattr(indexer, "write_checkpoint", lambda value, state: checkpoint_writes.append(state))
    monkeypatch.setattr(indexer, "iter_indicator_pages", iter_pages)
    monkeypatch.setattr(indexer, "_index_batch", lambda value, entities: len(entities))

    indexed, watermark = indexer._run_index_cycle(None)

    assert indexed == 2
    assert watermark == "2026-07-13T10:00:00.000Z"
    assert iterator_calls == [
        {
            "since": None,
            "upper_bound": "2026-07-13T10:00:00.000Z",
            "after": "cursor-1",
            "page_size": 100,
            "curated_ids": None,
        }
    ]
    assert checkpoint_writes[0]["scan_after"] == "cursor-2"
    assert checkpoint_writes[0]["scan_processed"] == 101
    assert checkpoint_writes[-1] == {
        "last_indexed_at": "2026-07-13T10:00:00.000Z",
        "scan_mode": "",
        "scan_upper_bound": "",
        "scan_after": "",
        "scan_processed": 0,
    }
