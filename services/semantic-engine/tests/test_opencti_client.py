from unittest.mock import MagicMock, call

import pytest

import opencti_client


def _page(ids, *, end_cursor, has_next, global_count=4):
    return {
        "entities": [
            {"id": indicator_id, "updated_at": f"2026-07-13T10:00:0{position}.000Z"}
            for position, indicator_id in enumerate(ids)
        ],
        "pagination": {
            "endCursor": end_cursor,
            "hasNextPage": has_next,
            "globalCount": global_count,
        },
    }


def test_iter_indicator_pages_uses_bounded_cursor_window():
    client = MagicMock()
    client.indicator.list.side_effect = [
        _page(["indicator--1", "indicator--2"], end_cursor="cursor-1", has_next=True),
        _page(["indicator--3", "indicator--4"], end_cursor="cursor-2", has_next=False),
    ]

    pages = list(
        opencti_client.iter_indicator_pages(
            client,
            since="2026-07-12T00:00:00.000Z",
            upper_bound="2026-07-13T10:00:00.000Z",
            page_size=100,
        )
    )

    assert len(pages) == 2
    filters = {
        "mode": "and",
        "filters": [
            {
                "key": "updated_at",
                "values": ["2026-07-12T00:00:00.000Z"],
                "operator": "gt",
                "mode": "or",
            },
            {
                "key": "updated_at",
                "values": ["2026-07-13T10:00:00.000Z"],
                "operator": "lte",
                "mode": "or",
            },
        ],
        "filterGroups": [],
    }
    expected_common = {
        "first": 100,
        "withPagination": True,
        "orderBy": "updated_at",
        "orderMode": "asc",
        "filters": filters,
    }
    assert client.indicator.list.call_args_list == [
        call(after=None, **expected_common),
        call(after="cursor-1", **expected_common),
    ]
    assert all("getAll" not in item.kwargs for item in client.indicator.list.call_args_list)


def test_iter_indicator_pages_honors_resume_cursor_and_rejects_oversized_page():
    client = MagicMock()
    client.indicator.list.return_value = _page(
        ["indicator--3"], end_cursor="cursor-3", has_next=False
    )

    list(
        opencti_client.iter_indicator_pages(
            client,
            since=None,
            upper_bound="2026-07-13T10:00:00.000Z",
            after="resume-cursor",
        )
    )

    assert client.indicator.list.call_args.kwargs["after"] == "resume-cursor"
    assert client.indicator.list.call_args.kwargs["first"] == 100

    with pytest.raises(ValueError, match="page_size"):
        list(
            opencti_client.iter_indicator_pages(
                client,
                since=None,
                upper_bound="2026-07-13T10:00:00.000Z",
                page_size=101,
            )
        )


def test_iter_indicator_pages_rejects_missing_next_cursor():
    client = MagicMock()
    client.indicator.list.return_value = _page(
        ["indicator--1"], end_cursor="", has_next=True
    )

    with pytest.raises(RuntimeError, match="endCursor"):
        list(
            opencti_client.iter_indicator_pages(
                client,
                since=None,
                upper_bound="2026-07-13T10:00:00.000Z",
            )
        )


def test_iter_indicator_pages_retries_transient_opencti_failure(monkeypatch):
    client = MagicMock()
    client.indicator.list.side_effect = [
        RuntimeError("DATABASE_ERROR: Find direct ids fail"),
        _page(["indicator--1"], end_cursor="cursor-1", has_next=False),
    ]
    waits = []
    monkeypatch.setattr(opencti_client.time, "sleep", waits.append, raising=False)

    pages = list(
        opencti_client.iter_indicator_pages(
            client,
            since=None,
            upper_bound="2026-07-13T10:00:00.000Z",
        )
    )

    assert len(pages) == 1
    assert client.indicator.list.call_count == 2
    assert waits == [opencti_client.PAGE_RETRY_DELAYS[0]]
