"""Validate published artifact hashes; does not claim visual or runtime acceptance."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]
sources={s['source_id'] for s in json.loads((root/'provenance.json').read_text())['sources']}
count=0
for manifest in (root/'docs').rglob('*artifacts.json'):
    data=json.loads(manifest.read_text())
    assert data['migration_status']=='partial'
    for item in data['artifacts']:
        assert set(item['source_ids']).issubset(sources), item['path']
        path=(root/item['path']).resolve()
        assert path.is_relative_to((root/'docs').resolve())
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']
        count+=1
print(json.dumps({'evidence_class':'artifact_integrity','files':count,'status':'passed','runtime_acceptance':'not_run'}))
