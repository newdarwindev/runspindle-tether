#!/usr/bin/env python3
"""Verify immutable pinned inputs into a fresh private job copy; no npm/network."""

from __future__ import annotations

import hashlib
import io
import os
import posixpath
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = Path("/home/runner/preparation/quality-node-modules.tar.gz")
ARCHIVE_SHA = "ec040b616152ddaecc4d8324639e2097b320078aafbe3ed08bb90f92d09dda23"
PINS = {
    "package.json": "728009d6ffdd0ae4629f8d55c43e8ac43c7a90ba9925b92fbdafb86e7092f752",
    "package-lock.json": "8f74da4ed2179fc535f4d8a261d1a46683f3e244ad02362e53336e39b30f48db",
}


def read_archive(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 12 * 1024 * 1024:
            raise ValueError("Invalid cache archive")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(12 * 1024 * 1024 + 1)
        if (
            len(raw) > 12 * 1024 * 1024
            or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA
        ):
            raise ValueError("Pinned cache archive mismatch")
        return raw
    finally:
        os.close(fd)


def inventory(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    entries: dict[str, tarfile.TarInfo] = {}
    total = 0
    for item in archive:
        name = item.name.rstrip("/")
        path = PurePosixPath(name)
        if (
            len(entries) >= 10000
            or len(name) > 1024
            or name in entries
            or path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != "node_modules"
            or str(path) != name
        ):
            raise ValueError("Unsafe or excessive archive paths")
        if not (item.isdir() or item.isfile() or item.issym()) or item.size < 0:
            raise ValueError("Unsupported archive member")
        total += item.size
        if total > 128 * 1024 * 1024:
            raise ValueError("Unpacked cache bound exceeded")
        entries[name] = item
    for name, item in entries.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) in entries and not entries[str(parent)].isdir():
                raise ValueError("Non-directory archive parent")
        if item.issym():
            # Only standard executable shims, pointing directly to regular files.
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(name), item.linkname)
            )
            if (
                PurePosixPath(name).parent != PurePosixPath("node_modules/.bin")
                or len(item.linkname) > 1024
                or target not in entries
                or not entries[target].isfile()
            ):
                raise ValueError("Unsafe executable shim")
    if "node_modules" not in entries or not entries["node_modules"].isdir():
        raise ValueError("Missing modules root")
    return list(entries.values())


def stage(root: Path = ROOT, source: Path = ARCHIVE) -> None:
    target = root / "tools/quality-node"
    if target.resolve(strict=True) != target:
        raise ValueError("Noncanonical job destination")
    for name, digest in PINS.items():
        path = target / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Dependency lock differs from qualified input")
    destination = target / "node_modules"
    if destination.exists() or destination.is_symlink():
        raise ValueError("Job dependency destination already exists")
    raw = read_archive(source)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        entries = inventory(archive)
        with tempfile.TemporaryDirectory(
            prefix=".private-node-", dir=target
        ) as directory:
            private = Path(directory)
            for item in entries:
                path = private / item.name
                if item.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif item.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise ValueError("Missing file body")
                    with stream, path.open("xb") as out:
                        while chunk := stream.read(1024 * 1024):
                            out.write(chunk)
                    path.chmod(0o755 if item.mode & 0o111 else 0o644)
            for item in entries:
                if item.issym():
                    (private / item.name).symlink_to(item.linkname)
            # No hardlinks/reflinks/shared writable targets; publish complete copy.
            if destination.exists() or destination.is_symlink():
                raise ValueError("Destination appeared during staging")
            (private / "node_modules").rename(destination)


if __name__ == "__main__":
    stage()
