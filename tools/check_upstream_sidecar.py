#!/usr/bin/env python3
"""Isolated original-upstream adapter tests; never activates chat or model clients."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runspindle_tether.source_gate import verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('tether', type=Path)
    parser.add_argument('agent_tether', type=Path)
    args = parser.parse_args()
    roots = [args.agent_tether.resolve()/'src', args.tether.resolve()/'agent', ROOT]
    for name,path in [('tether',args.tether),('agent-tether',args.agent_tether)]:
        verify(path.resolve(), name, ROOT/'upstream/pins.json')
    code = 'import sys,unittest; sys.path[:0]='+repr([str(p) for p in roots])+'; suite=unittest.defaultTestLoader.discover('+repr(str(ROOT/'upstream/tests'))+'); result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not result.wasSuccessful())'
    env = {'PATH': os.environ.get('PATH',''), 'PYTHONDONTWRITEBYTECODE':'1'}
    result = subprocess.run([sys.executable,'-I','-B',*(['-O'] if sys.flags.optimize else []),'-c',code],env=env,timeout=60)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
