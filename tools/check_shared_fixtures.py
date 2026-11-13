#!/usr/bin/env python3
"""Offline pinned test-fixture conformance; never runtime acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = {'artifact.txt', 'contract.json', 'fixturekit.py', 'golden.json', 'vectors.json'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root=ROOT):
    root = Path(root)
    pin = json.loads((root / 'fixtures/shared-v1.pin.json').read_text())
    bundle = root / 'fixtures/shared-v1'
    manifest_path = bundle / 'manifest.json'
    if pin['repository'] != 'newdarwindev/runspindle' or not re.fullmatch('[0-9a-f]{40}', pin['source_commit']):
        raise ValueError('invalid-source-pin')
    if manifest_path.is_symlink() or digest(manifest_path) != pin['subset_manifest_sha256']:
        raise ValueError('subset-pin-mismatch')
    manifest = json.loads(manifest_path.read_text())
    if (manifest['schema'] != pin['schema'] or manifest['component'] != pin['component']
            or manifest['origin_manifest_sha256'] != pin['origin_manifest_sha256']):
        raise ValueError('origin-pin-mismatch')
    if set(manifest['files']) != FILES or {p.name for p in bundle.iterdir() if p.name != '__pycache__'} != FILES | {'manifest.json'}:
        raise ValueError('inventory-mismatch')
    # Verify every byte against the independently reviewed pin chain BEFORE import.
    for name, expected in manifest['files'].items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('file-digest-mismatch')
    spec = importlib.util.spec_from_file_location('pinned_fixturekit', bundle / 'fixturekit.py')
    kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)
    kit.verify_bundle(bundle)
    golden = kit.load_json(bundle / 'golden.json')
    vectors = kit.load_json(bundle / 'vectors.json')
    if not golden or not vectors:
        raise ValueError('empty-conformance-lane')
    for fixture in golden:
        identity = copy.deepcopy(fixture['identity'])
        observations = {fixture['state']: {'identity': copy.deepcopy(identity), 'detail': copy.deepcopy(fixture['detail'])},
                        'accepted_digest': identity.get('artifact_digest'), 'approved_digest': identity.get('candidate_digest')}
        kit.assert_conforms(copy.deepcopy(fixture), identity, fixture['state'], observations)
        for vector in [v for v in vectors if v['kind'] == fixture['kind']]:
            mutated = copy.deepcopy(fixture)
            target = mutated
            for name in vector['mutation']['path'][:-1]:
                target = target[name]
            target[vector['mutation']['path'][-1]] = vector['mutation']['value']
            try:
                kit.assert_conforms(mutated, identity, fixture['state'], observations)
            except kit.ContractError as error:
                if str(error) != vector['expected_error']:
                    raise ValueError('wrong-vector-error: ' + vector['id']) from error
            else:
                raise ValueError('undetected-vector: ' + vector['id'])
    return {'status': 'passed', 'component': pin['component'], 'golden': len(golden),
            'negative_vectors': len(vectors), 'evidence_class': 'synthetic_fixture_conformance',
            'runtime_adapter': 'not_implemented', 'integration': 'not_run', 'live_acceptance': 'not_run'}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
