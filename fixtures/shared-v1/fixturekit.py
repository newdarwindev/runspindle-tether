"""Provisional synthetic contracts; no runtime authority or upstream compatibility."""
import hashlib
import json
import random
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

VERSION = 'runspindle.fixture.v1'
MAX_BYTES = 65536
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
STATUSES = {'not-run', 'passed', 'failed', 'blocked', 'unknown'}


class ContractError(ValueError):
    pass


def reject(code):
    raise ContractError(code)


def load_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        reject('size')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                reject('duplicate-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _keys(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys():
        reject('required-keys')
    if value.keys() - set(required) - set(optional):
        reject('unknown-key')


def _field(value, rule):
    if rule == 'id':
        valid = type(value) is str and ID.fullmatch(value)
    elif rule == 'digest':
        valid = type(value) is str and DIGEST.fullmatch(value)
    elif rule == 'positive':
        valid = type(value) is int and 0 < value <= 2**53 - 1
    elif rule == 'counter':
        valid = type(value) is int and 0 <= value <= 2**53 - 1
    elif rule == 'origin':
        valid = type(value) is str and re.fullmatch(r'https://[a-z0-9-]+\.example', value)
    elif rule == 'timestamp':
        valid = False
        if type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
            try:
                datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
                valid = True
            except ValueError:
                pass
    else:
        reject('contract-rule')
    if not valid:
        reject('field-type-or-bound')


def validate(envelope, contract=None):
    """Validate syntax only. A valid envelope is never proof of an effect."""
    try:
        encoded = json.dumps(envelope, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        reject('serialization')
    if len(encoded) > MAX_BYTES:
        reject('size')
    contract = contract or load_json(Path(__file__).with_name('contract.json'))
    _keys(envelope, ['schema', 'kind', 'identity', 'state', 'status', 'observed_at', 'evidence_class', 'detail'])
    if envelope['schema'] != VERSION:
        reject('schema-version')
    kind = envelope['kind']
    if type(kind) is not str or kind not in contract['kinds']:
        reject('unknown-event')
    spec = contract['kinds'][kind]
    if envelope['evidence_class'] != 'synthetic_fixture':
        reject('evidence-class')
    if type(envelope['status']) is not str or envelope['status'] not in STATUSES:
        reject('status')
    if type(envelope['state']) is not str or envelope['state'] not in spec['states']:
        reject('state')
    if envelope['state'] in ['unknown', 'blocked', 'not-run'] and envelope['status'] == 'passed':
        reject('uncertainty-is-not-success')
    _field(envelope['observed_at'], 'timestamp')
    identity = envelope['identity']
    required = contract['common_identity'] + spec['identity']
    _keys(identity, required)
    for name, value in identity.items():
        _field(value, contract['identity_fields'][name])
    _keys(envelope['detail'], spec['detail'])
    for name, rule in spec['detail'].items():
        _field(envelope['detail'][name], rule)
    return envelope


def assert_conforms(envelope, expected_identity, expected_state, observations=None):
    """Test oracle: bind to independent request/spy observations, never event flags.

    The caller supplies synthetic observations recorded outside the adapter under
    test. These are not authenticated runtime receipts or an authorization API.
    """
    validate(envelope)
    if envelope['identity'] != expected_identity:
        reject('identity-mismatch')
    if envelope['state'] != expected_state or envelope['status'] != 'passed':
        reject('outcome-mismatch')
    observations = observations or {}
    if envelope['state'] in ['delivered', 'persisted', 'serving']:
        receipt = observations.get(envelope['state'])
        if receipt != {'identity': expected_identity, 'detail': envelope['detail']}:
            reject('missing-independent-receipt')
    if envelope['kind'] == 'artifact.observed' and envelope['state'] == 'delivered':
        if observations.get('accepted_digest') != expected_identity.get('artifact_digest'):
            reject('unaccepted-bytes')
    if envelope['state'] == 'serving':
        if observations.get('approved_digest') != expected_identity.get('candidate_digest'):
            reject('unapproved-candidate')
    return True


def aggregate(statuses):
    """No empty or incomplete required lane may become a successful aggregate."""
    statuses = list(statuses)
    if not statuses or any(type(s) is not str or s not in STATUSES for s in statuses):
        reject('status')
    return 'passed' if all(s == 'passed' for s in statuses) else 'blocked'


def verify_bundle(directory):
    root = Path(directory).resolve()
    manifest = load_json(root / 'manifest.json')
    if manifest['schema'] != VERSION:
        reject('schema-version')
    expected_files = set(manifest['files']) | {'manifest.json'}
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    if actual_files != expected_files:
        reject('bundle-inventory')
    for name, digest in manifest['files'].items():
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            reject('bundle-path')
        _field(digest, 'digest')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            reject('bundle-digest')
    fixtures = load_json(root / 'golden.json')
    contract = load_json(root / 'contract.json')
    for fixture in fixtures:
        validate(fixture, contract)
        if 'artifact_digest' in fixture['identity']:
            if fixture['identity']['artifact_digest'] != hashlib.sha256((root / 'artifact.txt').read_bytes()).hexdigest():
                reject('artifact-digest')
    return manifest


def export_bundle(component, destination):
    """Export a verified, standalone component subset; destination must be new."""
    root = Path(__file__).resolve().parent
    manifest = verify_bundle(root)
    components = manifest['components']
    if component not in components:
        reject('component')
    destination = Path(destination)
    destination.mkdir(parents=False, exist_ok=False)
    try:
        for name in ['fixturekit.py', 'contract.json', 'artifact.txt']:
            shutil.copyfile(root / name, destination / name)
        fixtures = [x for x in load_json(root / 'golden.json') if x['kind'] in components[component]]
        (destination / 'golden.json').write_text(json.dumps(fixtures, indent=2, sort_keys=True) + '\n')
        vectors = [x for x in load_json(root / 'vectors.json') if x['kind'] in components[component]]
        (destination / 'vectors.json').write_text(json.dumps(vectors, indent=2, sort_keys=True) + '\n')
        result = {'schema': VERSION, 'component': component, 'origin_manifest_sha256': hashlib.sha256((root / 'manifest.json').read_bytes()).hexdigest(), 'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(destination.iterdir())}}
        (destination / 'manifest.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        verify_bundle(destination)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return result


class Spy:
    """Default-deny fake transport; only explicit synthetic calls are allowed."""
    def __init__(self, allowed=()):
        self.allowed = set(allowed)
        self.calls = []

    def call(self, operation, identity):
        self.calls.append((operation, dict(identity)))
        if operation not in self.allowed:
            reject('forbidden-call')


class Clock:
    def __init__(self, seconds=0):
        self.seconds = seconds

    def advance(self, seconds):
        if type(seconds) is not int or seconds < 0:
            reject('clock')
        self.seconds += seconds


class Ids:
    def __init__(self, seed):
        self.random = random.Random(seed)

    def next(self):
        return 'synthetic-' + format(self.random.getrandbits(64), '016x')


@contextmanager
def temporary_store():
    """Disposable fixture directory; this helper makes no durability guarantee."""
    with tempfile.TemporaryDirectory(prefix='runspindle-fixture-') as directory:
        yield Path(directory)


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == 'export':
            export_bundle(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 1:
            verify_bundle(Path(__file__).resolve().parent)
        else:
            reject('usage: fixturekit.py [export COMPONENT NEW_DIRECTORY]')
        print(json.dumps({'status': 'passed', 'evidence_class': 'synthetic_fixture_integrity', 'integration': 'not-run', 'live_acceptance': 'not-run'}))
    except (ContractError, OSError, KeyError, ValueError) as error:
        print(json.dumps({'status': 'failed', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)
