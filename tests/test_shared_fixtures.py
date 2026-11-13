"""Consumer pin-chain and independent oracle regression tests, offline only."""
import hashlib
import importlib.util
import json
import marshal
import struct
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('consumer_check', ROOT / 'tools/check_shared_fixtures.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class SharedFixtureTests(unittest.TestCase):
    def test_all_pinned_vectors_without_network(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')) as network:
            report = consumer.check()
        network.assert_not_called()
        self.assertEqual(report['status'], 'passed')
        self.assertGreater(report['golden'], 0)
        self.assertGreater(report['negative_vectors'], 0)
        self.assertEqual(report['integration'], 'not_run')

    def temporary_copy(self):
        temporary = tempfile.TemporaryDirectory(prefix='runspindle-fixture-consumer-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        shutil.copytree(ROOT / 'fixtures', root / 'fixtures', ignore=shutil.ignore_patterns('__pycache__'))
        return root

    def test_corrupt_validator_rejected_before_import(self):
        root = self.temporary_copy()
        path = root / 'fixtures/shared-v1/fixturekit.py'
        path.write_text('raise AssertionError("must not import unpinned code")\n')
        with self.assertRaisesRegex(ValueError, 'file-digest-mismatch'):
            consumer.check(root)

    def test_self_rehashed_tampering_does_not_update_reviewed_pin(self):
        root = self.temporary_copy()
        path = root / 'fixtures/shared-v1/artifact.txt'
        path.write_bytes(b'changed synthetic bytes')
        manifest_path = root / 'fixtures/shared-v1/manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files']['artifact.txt'] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'subset-pin-mismatch'):
            consumer.check(root)

    def test_wrong_origin_pin_rejected(self):
        root = self.temporary_copy()
        path = root / 'fixtures/shared-v1.pin.json'
        pin = json.loads(path.read_text())
        pin['origin_manifest_sha256'] = '0' * 64
        path.write_text(json.dumps(pin))
        with self.assertRaisesRegex(ValueError, 'origin-pin-mismatch'):
            consumer.check(root)

    def test_matching_unreviewed_bytecode_cache_is_never_executed(self):
        root = self.temporary_copy()
        source = root / 'fixtures/shared-v1/fixturekit.py'
        # Keep every cache byte inside the disposable test root, including macOS.
        with patch('sys.pycache_prefix', None):
            cached = Path(importlib.util.cache_from_source(str(source)))
            cached.parent.mkdir()
            stats = source.stat()
            header = importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(stats.st_mtime), stats.st_size)
            poison = compile('raise AssertionError("unreviewed bytecode executed")', str(source), 'exec')
            cached.write_bytes(header + marshal.dumps(poison))
            # Negative control proves this cache is executable by the former loader.
            broken = importlib.util.spec_from_file_location('broken_fixture_loader', source)
            with self.assertRaisesRegex(AssertionError, 'unreviewed bytecode executed'):
                broken.loader.exec_module(importlib.util.module_from_spec(broken))
            self.assertEqual(consumer.check(root)['status'], 'passed')

    def test_unexpected_bundle_file_rejected(self):
        root = self.temporary_copy()
        (root / 'fixtures/shared-v1/unexpected.txt').write_text('synthetic')
        with self.assertRaisesRegex(ValueError, 'inventory-mismatch'):
            consumer.check(root)


if __name__ == '__main__':
    unittest.main()
