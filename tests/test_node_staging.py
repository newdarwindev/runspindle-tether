"""Offline cache integrity/path negatives; no host cache writes."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools import stage_node_quality as stage


def tar(items: list[tuple[str, bytes, str]]) -> tarfile.TarFile:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, data, link in items:
            item = tarfile.TarInfo(name)
            if name.endswith("/"):
                item.type = tarfile.DIRTYPE
            elif link:
                item.type = tarfile.SYMTYPE
                item.linkname = link
            else:
                item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    raw.seek(0)
    return tarfile.open(fileobj=raw, mode="r:")


class NodeStagingTests(unittest.TestCase):
    def test_regular_internal_executable_shim_allowed(self) -> None:
        with tar(
            [
                ("node_modules/", b"", ""),
                ("node_modules/.bin/", b"", ""),
                ("node_modules/tool.js", b"x", ""),
                ("node_modules/.bin/tool", b"", "../tool.js"),
            ]
        ) as archive:
            self.assertEqual(len(stage.inventory(archive)), 4)

    def test_escape_and_non_directory_parent_rejected(self) -> None:
        cases = [
            [("node_modules/", b"", ""), ("../escape", b"x", "")],
            [
                ("node_modules/", b"", ""),
                ("node_modules/.bin/", b"", ""),
                ("node_modules/.bin/tool", b"", "../../../escape"),
            ],
            [
                ("node_modules/", b"", ""),
                ("node_modules/file", b"x", ""),
                ("node_modules/file/child", b"x", ""),
            ],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tar(entries) as archive:
                with self.assertRaises(ValueError):
                    stage.inventory(archive)

    def test_changed_or_linked_archive_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive"
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                stage.read_archive(path)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                stage.read_archive(link)
