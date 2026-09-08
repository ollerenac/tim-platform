from __future__ import annotations

import hashlib
import os

import pytest

from exp02 import jsonio
from exp02.jsonio import load_json, sha256_file, write_new_json


def test_write_new_json_is_canonical_and_exclusive(tmp_path):
    target = tmp_path / "record.json"

    digest = write_new_json(target, {"z": 1, "a": "á"})

    assert target.read_bytes() == b'{"a":"\xc3\xa1","z":1}\n'
    assert digest == sha256_file(target)
    with pytest.raises(FileExistsError):
        write_new_json(target, {"a": 2})


def test_load_json_rejects_duplicate_keys(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"id":"a","id":"b"}')

    with pytest.raises(ValueError, match="duplicate JSON key: id"):
        load_json(path)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_write_new_json_rejects_non_finite_numbers(tmp_path, value):
    with pytest.raises(ValueError):
        write_new_json(tmp_path / "record.json", {"value": value})


@pytest.mark.parametrize("payload", ["[]", "null", '"text"', "1"])
def test_load_json_requires_an_object_root(tmp_path, payload):
    path = tmp_path / "not-an-object.json"
    path.write_text(payload)

    with pytest.raises(ValueError, match="JSON root must be an object"):
        load_json(path)


@pytest.mark.parametrize("payload", ['{"value":NaN}', '{"value":Infinity}'])
def test_load_json_rejects_non_finite_numbers(tmp_path, payload):
    path = tmp_path / "non-finite.json"
    path.write_text(payload)

    with pytest.raises(ValueError, match="non-finite JSON number"):
        load_json(path)


def test_load_json_rejects_symlinks(tmp_path):
    target = tmp_path / "target.json"
    target.write_text('{"id":"record"}')
    link = tmp_path / "link.json"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        load_json(link)


def test_load_json_rejects_symlinked_parent_directories(tmp_path):
    trusted_parent = tmp_path / "trusted"
    trusted_parent.mkdir()
    target = trusted_parent / "record.json"
    target.write_text('{"id":"record"}')
    link_parent = tmp_path / "linked-parent"
    link_parent.symlink_to(trusted_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        load_json(link_parent / "record.json")


def test_load_json_rejects_files_over_twenty_mib(tmp_path):
    path = tmp_path / "too-large.json"
    path.write_bytes(b" " * (20 * 1024 * 1024 + 1))

    with pytest.raises(ValueError, match="20 MiB"):
        load_json(path)


def test_sha256_file_hashes_large_files_in_streaming_blocks(tmp_path):
    path = tmp_path / "large.bin"
    data = b"a" * (1024 * 1024 + 1)
    path.write_bytes(data)

    assert sha256_file(path) == hashlib.sha256(data).hexdigest()


def test_sha256_file_rejects_symlinks(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"frozen artifact")
    link = tmp_path / "link.bin"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        sha256_file(link)


def test_write_new_json_rejects_symlinked_parent_directories(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link_parent = tmp_path / "linked-parent"
    link_parent.symlink_to(outside, target_is_directory=True)
    target = link_parent / "record.json"

    with pytest.raises(ValueError, match="symlink"):
        write_new_json(target, {"id": "record"})

    assert not (outside / "record.json").exists()


def test_load_json_keeps_the_checked_parent_when_path_is_replaced(tmp_path, monkeypatch):
    parent = tmp_path / "trusted"
    parent.mkdir()
    record = parent / "record.json"
    record.write_text('{"id":"trusted"}')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "record.json").write_text('{"id":"outside"}')
    replacement = tmp_path / "trusted-before-replacement"
    original_open_directory = jsonio._open_directory
    replaced = False

    def replace_after_parent_open(component: str, parent_fd: int):
        nonlocal replaced
        descriptor = original_open_directory(component, parent_fd)
        if component == parent.name and not replaced:
            os.rename(parent, replacement)
            parent.symlink_to(outside, target_is_directory=True)
            replaced = True
        return descriptor

    monkeypatch.setattr(jsonio, "_open_directory", replace_after_parent_open)

    assert load_json(record) == {"id": "trusted"}
