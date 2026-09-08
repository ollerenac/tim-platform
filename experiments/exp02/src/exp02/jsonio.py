"""Strict canonical JSON helpers for frozen experiment artifacts."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_JSON_BYTES = 20 * 1024 * 1024
HASH_BLOCK_SIZE = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW
_WRITE_NEW_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    _DIRECTORY_FLAGS |= os.O_CLOEXEC
    _READ_FLAGS |= os.O_CLOEXEC
    _WRITE_NEW_FLAGS |= os.O_CLOEXEC


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def canonical_bytes(value: object) -> bytes:
    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (text + "\n").encode("utf-8")


def _raise_if_link_or_not_directory(component: str, error: OSError) -> None:
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise ValueError(
            f"refusing symlink or non-directory path component: {component}"
        ) from error
    raise error


def _open_directory(component: str, parent_fd: int) -> int:
    try:
        return os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        _raise_if_link_or_not_directory(component, error)
        raise AssertionError("unreachable")


def _split_path(path: Path | str) -> tuple[int, list[str]]:
    file_path = Path(path)
    if file_path.is_absolute():
        directory_fd = os.open("/", _DIRECTORY_FLAGS)
        components = list(file_path.parts[1:])
    else:
        directory_fd = os.open(".", _DIRECTORY_FLAGS)
        components = list(file_path.parts)
    if not components or any(component in {"", ".", ".."} for component in components):
        os.close(directory_fd)
        raise ValueError("artifact path must name a file without dot segments")
    return directory_fd, components


def _open_parent_directory(path: Path | str, *, create: bool) -> tuple[int, str]:
    directory_fd, components = _split_path(path)
    filename = components.pop()
    try:
        for component in components:
            try:
                child_fd = _open_directory(component, directory_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                child_fd = _open_directory(component, directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd, filename


def _open_existing_file(path: Path | str) -> int:
    parent_fd, filename = _open_parent_directory(path, create=False)
    try:
        return os.open(filename, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"refusing symlink artifact file: {filename}") from error
        raise
    finally:
        os.close(parent_fd)


def _open_new_file(path: Path | str) -> int:
    parent_fd, filename = _open_parent_directory(path, create=True)
    try:
        return os.open(filename, _WRITE_NEW_FLAGS, 0o666, dir_fd=parent_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"refusing symlink artifact file: {filename}") from error
        raise
    finally:
        os.close(parent_fd)


def _validate_regular_file(file_descriptor: int) -> int:
    size = os.fstat(file_descriptor).st_size
    if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
        raise ValueError("artifact path must refer to a regular file")
    return size


def load_json(path: Path | str) -> dict[str, Any]:
    """Load one small JSON object while rejecting ambiguous input forms."""
    file_descriptor = _open_existing_file(path)
    try:
        if _validate_regular_file(file_descriptor) > MAX_JSON_BYTES:
            raise ValueError("JSON file exceeds 20 MiB limit")
        handle = os.fdopen(file_descriptor, "r", encoding="utf-8")
    except BaseException:
        os.close(file_descriptor)
        raise
    with handle:
        value = json.load(
            handle,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_non_finite,
        )
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def sha256_file(path: Path | str) -> str:
    """Return a SHA-256 digest while reading at most one MiB per chunk."""
    digest = hashlib.sha256()
    file_descriptor = _open_existing_file(path)
    try:
        _validate_regular_file(file_descriptor)
        handle = os.fdopen(file_descriptor, "rb")
    except BaseException:
        os.close(file_descriptor)
        raise
    with handle:
        for block in iter(lambda: handle.read(HASH_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new_json(path: Path | str, value: object) -> str:
    """Write canonical JSON once, never overwriting a frozen artifact."""
    data = canonical_bytes(value)
    file_descriptor = _open_new_file(path)
    with os.fdopen(file_descriptor, "xb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()
