"""Verify explicitly selected upstream source before isolated imports."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def verify(root: Path, name: str, manifest: Path) -> dict:
    entry = json.loads(manifest.read_text())[name]
    def git(*args):
        return subprocess.check_output(['git','-C',str(root),*args], text=True).strip()
    if git('rev-parse','HEAD') != entry['commit'] or git('rev-parse','HEAD^{tree}') != entry['tree']:
        raise ValueError('unreviewed upstream revision')
    if git('status','--porcelain','--untracked-files=all','--ignored'):
        raise ValueError('upstream checkout must be immutable and clean')
    for relative, expected in entry['files'].items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('upstream source identity mismatch')
    return entry
