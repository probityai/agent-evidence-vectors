"""Check exact original/selected ZIP members against the public retention receipt."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('name', ['langgraph-durable-2026-10-02',
    'pydantic-failure-2026-10-02', 'model-operational-2026-10-02',
    'authority-recovery-2026-10-02', 'target-process-recovery-2026-10-02',
    'model-paired-cpu-2026-10-02', 'openai-agents-ticket-2026-10-02',
    'execsurface-state-2026-10-02', 'model-format-cpu-2026-10-02', 'google-adk-ticket-2026-10-02',
    'installed-format-policy-2026-10-02'])
def test_public_archive_preserves_selected_original_members(name: str) -> None:
    folder = ROOT / 'experiments' / name
    provenance = json.loads((folder / 'provenance.json').read_bytes())
    archive = folder / ('selected-capsule.zip' if name == 'model-operational-2026-10-02' else 'original-artifact.zip')
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == provenance['retainedArchiveSha256']
    selected = {item['member']: item for item in provenance['members'] if item['selected']}
    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == set(selected)
        for member, pin in selected.items():
            raw = bundle.read(member)
            assert len(raw) == pin['bytes']
            assert hashlib.sha256(raw).hexdigest() == pin['sha256']
        assert bundle.read(provenance['reportMember']) == (folder / 'report.json').read_bytes()
    assert provenance['roles']['independentEffectCustody'] == 'not-established'


def model_provenance() -> dict:
    """Read the public original compact/full preparation mapping."""
    path = ROOT / 'experiments' / 'model-paired-cpu-2026-10-02' / 'provenance.json'
    return json.loads(path.read_bytes())


def check_full_mapping(provenance: dict) -> None:
    """Refuse invented compact identity, mismapped native bytes or hidden omissions."""
    compact = {item['member']: item for item in provenance['members']}
    full = provenance['fullPreparationMembers']
    summary = provenance['fullPreparationArchive']
    assert len({item['member'] for item in full}) == len(full) == summary['memberCount'] == 276
    selected = [item for item in full if item['retainedInCompact']]
    omitted = [item for item in full if not item['retainedInCompact']]
    assert len(selected) == len(compact) == summary['publiclyRetainedNativeMembers'] == 246
    assert len(omitted) == summary['omittedPreparationMembers'] == 30
    assert {item['compactMember'] for item in selected} == set(compact)
    for item in selected:
        assert item['member'] == 'run/' + item['compactMember']
        actual = compact[item['compactMember']]
        assert (item['sha256'], item['bytes']) == (actual['sha256'], actual['bytes'])
    assert all(item['compactMember'] is None for item in omitted)
    assert {'smol135-q4.gguf', 'smol360-q4.gguf'} <= {item['member'] for item in omitted}
    history = provenance['preparationHistory']
    assert history['cumulativeResponseBodyBytesAcrossTwoPreparations'] == (
        history['initialNoInferenceFailureResponseBodyBytes'] +
        history['correctedSuccessfulResponseBodyBytes'])
    assert history['cumulativeResponseBodyBytesAcrossTwoPreparations'] > 512 * 1024 * 1024


def test_full_preparation_mapping_preserves_native_bytes_and_omissions() -> None:
    check_full_mapping(model_provenance())


@pytest.mark.parametrize('field,value', [
    ('memberCount', 275), ('publiclyRetainedNativeMembers', 245),
    ('omittedPreparationMembers', 0)])
def test_changed_preparation_counts_refuse(field: str, value: int) -> None:
    provenance = model_provenance()
    provenance['fullPreparationArchive'][field] = value
    with pytest.raises(AssertionError):
        check_full_mapping(provenance)


def test_full_preparation_rebound_native_member_refuses() -> None:
    provenance = model_provenance()
    item = next(m for m in provenance['fullPreparationMembers'] if m['retainedInCompact'])
    item['sha256'] = '0' * 64
    with pytest.raises(AssertionError):
        check_full_mapping(provenance)


def test_full_preparation_hidden_omission_refuses() -> None:
    provenance = model_provenance()
    item = next(m for m in provenance['fullPreparationMembers'] if not m['retainedInCompact'])
    item['retainedInCompact'] = True
    item['compactMember'] = 'report.json'
    with pytest.raises(AssertionError):
        check_full_mapping(provenance)


def test_cumulative_transfer_cannot_be_reported_as_one_preparation() -> None:
    provenance = model_provenance()
    history = provenance['preparationHistory']
    history['cumulativeResponseBodyBytesAcrossTwoPreparations'] = history['correctedSuccessfulResponseBodyBytes']
    with pytest.raises(AssertionError):
        check_full_mapping(provenance)


def format_inputs() -> tuple[dict, dict, dict]:
    """Load the selected index and exact report/provenance for semantic controls."""
    register = json.loads((ROOT / 'data/lab-register.json').read_bytes())
    record = next(r for r in register['records'] if r['id'] == 'model-format-cpu-2026-10-02')
    folder = ROOT / 'experiments/model-format-cpu-2026-10-02'
    return record, json.loads((folder / 'report.json').read_bytes()), json.loads((folder / 'provenance.json').read_bytes())


def test_selected_format_retention_preserves_all_rows_and_preparation() -> None:
    from tools.check_format_retention import validate_format_retention
    validate_format_retention(*format_inputs())


@pytest.mark.parametrize('mutation', [
    'schema-as-correctness', 'missing-row', 'pooled-decoder', 'renamed-row',
    'hidden-omission', 'rebound-native-member', 'one-preparation',
    'missing-original48-cost', 'invented-custody', 'unregistered-protocol'])
def test_selected_format_semantic_mutations_refuse(mutation: str) -> None:
    from tools.check_format_retention import validate_format_retention
    record, report, provenance = format_inputs()
    quality = [c for c in record['claimResults'] if c.get('recordedField', '').startswith('/quality/')]
    schema_policy = next(c for c in quality if c['expectedValue']['decoder'] == 'schema'
                         and c['expectedValue']['family'] == 'policy-decision')
    if mutation == 'schema-as-correctness':
        schema_policy['result'] = 'pass'
    elif mutation == 'missing-row':
        record['claimResults'].remove(quality[-1])
    elif mutation == 'pooled-decoder':
        report['quality'][0]['decoder'] = 'schema'
        quality[0]['expectedValue']['decoder'] = 'schema'
    elif mutation == 'renamed-row':
        schema_policy['claim'] = schema_policy['claim'].replace('strict-targets', 'schema-valid')
    elif mutation == 'hidden-omission':
        provenance['fullPreparationArchive']['omittedPreparationMembers'] = 0
    elif mutation == 'rebound-native-member':
        member = next(m for m in provenance['fullPreparationMembers'] if m['retainedInCompact'])
        member['sha256'] = '0' * 64
    elif mutation == 'one-preparation':
        provenance['preparationHistory']['allFourPreparationAttemptsBodyBytes'] = 472221945
    elif mutation == 'missing-original48-cost':
        provenance['preparationHistory']['original48RunBytes'] = 0
    elif mutation == 'invented-custody':
        provenance['roles']['independentEffectCustody'] = 'established'
    elif mutation == 'unregistered-protocol':
        provenance['protocolPreregistration']['publishedBeforeInference'] = False
    with pytest.raises(ValueError):
        validate_format_retention(record, report, provenance)


@pytest.mark.parametrize('mutation', ['protocol-rebind', 'compiler-rebind', 'native-member-rebind', 'schema-as-correctness'])
def test_reselected_format_receipt_semantics_refuse(tmp_path: Path, mutation: str) -> None:
    """Updating artifact SHA after tampering must not erase semantic refusals."""
    import shutil
    from tools.check_lab import validate_register
    record, report, provenance = format_inputs()
    folder = tmp_path / 'experiments/model-format-cpu-2026-10-02'
    shutil.copytree(ROOT / 'experiments/model-format-cpu-2026-10-02', folder)
    if mutation == 'protocol-rebind':
        provenance['protocolPreregistration']['sha256'] = '0' * 64
    elif mutation == 'compiler-rebind':
        provenance['protocolPreregistration']['compiler']['sourceSHA256'] = '0' * 64
    elif mutation == 'native-member-rebind':
        member = next(m for m in provenance['fullPreparationMembers'] if m['retainedInCompact'])
        pin = next(m for m in provenance['members'] if m['member'] == member['compactMember'])
        member['sha256'] = pin['sha256'] = '0' * 64
    else:
        claim = next(c for c in record['claimResults'] if c.get('recordedField', '').startswith('/quality/')
                     and c['expectedValue']['decoder'] == 'schema' and c['expectedValue']['family'] == 'policy-decision')
        claim['result'] = 'pass'
    (folder / 'provenance.json').write_text(json.dumps(provenance))
    for artifact in record['artifacts']:
        artifact['sha256'] = hashlib.sha256((folder / Path(artifact['path']).name).read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        validate_register({'protocolVersion': '0.1', 'records': [record]}, tmp_path)


def execution_inputs(name: str) -> tuple[dict, dict, dict]:
    """Load the complete selected SDK or installed-consumer original record."""
    register = json.loads((ROOT / 'data/lab-register.json').read_bytes())
    record = next(r for r in register['records'] if r['id'] == name)
    folder = ROOT / 'experiments' / name
    return record, json.loads((folder / 'report.json').read_bytes()), json.loads((folder / 'provenance.json').read_bytes())


@pytest.mark.parametrize('name', ['google-adk-ticket-2026-10-02', 'installed-format-policy-2026-10-02'])
def test_selected_execution_axes_are_separate(name: str) -> None:
    from tools.check_execution_retention import validate_execution_retention
    validate_execution_retention(*execution_inputs(name))


@pytest.mark.parametrize('mutation', ['committed-error-as-complete', 'scripted-model-quality',
    'unsupported-reader-publish', 'schema-hold-publish', 'quality-row-omission',
    'policy-schema-as-correctness', 'consumer-new-inference', 'invented-custody'])
def test_selected_execution_semantic_mutations_refuse(mutation: str) -> None:
    from tools.check_execution_retention import validate_execution_retention
    name = 'google-adk-ticket-2026-10-02' if mutation in ['committed-error-as-complete', 'scripted-model-quality'] else 'installed-format-policy-2026-10-02'
    record, report, provenance = execution_inputs(name)
    if mutation == 'committed-error-as-complete':
        i = next(i for i, r in enumerate(report['records']) if r['case'] == 'unhandled-after')
        c = next(c for c in record['claimResults'] if c.get('recordedField') == f'/records/{i}/taskStatus')
        c['result'] = 'pass'
    elif mutation == 'scripted-model-quality':
        report['modelQuality'] = 'evaluated'
    elif mutation == 'unsupported-reader-publish':
        report['baseline-format']['gate']['publicationDecision'] = 'publish'
    elif mutation == 'schema-hold-publish':
        report['candidate-format-quality']['gate']['publicationDecision'] = 'publish'
    elif mutation == 'quality-row-omission':
        report['candidate-format-quality']['gate']['policyFailures'].pop()
    elif mutation == 'policy-schema-as-correctness':
        report['candidate-format-quality']['gate']['policyFailures'][0]['field'] = 'schemaValid'
    elif mutation == 'consumer-new-inference':
        provenance['newInferenceExecuted'] = True
    else:
        provenance['roles']['independentEffectCustody'] = record['roles']['independentEffectCustody'] = 'established'
    with pytest.raises(ValueError):
        validate_execution_retention(record, report, provenance)


def test_reselected_ADK_commit_does_not_promote_failed_task(tmp_path: Path) -> None:
    import shutil
    from tools.check_lab import validate_register
    name = 'google-adk-ticket-2026-10-02'
    record, report, provenance = execution_inputs(name)
    folder = tmp_path / 'experiments' / name
    shutil.copytree(ROOT / 'experiments' / name, folder)
    i = next(i for i, r in enumerate(report['records']) if r['case'] == 'unhandled-after')
    claim = next(c for c in record['claimResults'] if c.get('recordedField') == f'/records/{i}/taskStatus')
    claim['result'] = 'pass'
    with pytest.raises(ValueError, match='task completion cannot be inferred'):
        validate_register({'protocolVersion': '0.1', 'records': [record]}, tmp_path)


def test_reselected_installed_policy_hold_cannot_be_publish(tmp_path: Path) -> None:
    import shutil
    from tools.check_lab import validate_register
    name = 'installed-format-policy-2026-10-02'
    record, report, provenance = execution_inputs(name)
    folder = tmp_path / 'experiments' / name
    shutil.copytree(ROOT / 'experiments' / name, folder)
    report['candidate-format-quality']['gate']['publicationDecision'] = 'publish'
    claim = next(c for c in record['claimResults'] if c.get('recordedField') == '/candidate-format-quality/gate/publicationDecision')
    claim['expectedValue'] = 'publish'
    (folder / 'report.json').write_text(json.dumps(report))
    for artifact in record['artifacts']:
        artifact['sha256'] = hashlib.sha256((folder / Path(artifact['path']).name).read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='verified evidence cannot promote failed selected quality'):
        validate_register({'protocolVersion': '0.1', 'records': [record]}, tmp_path)


@pytest.mark.parametrize('field,value', [('nativeRevision', True), ('nativeRevision', 1.0), ('taskStatus', True)])
def test_ADK_reselected_outcome_types_refuse(field: str, value: object) -> None:
    from tools.check_execution_retention import validate_execution_retention
    record, report, provenance = execution_inputs('google-adk-ticket-2026-10-02')
    report['records'][0][field] = value
    claim = next(c for c in record['claimResults'] if c.get('recordedField') == f'/records/0/{field}')
    claim['expectedValue'] = value
    with pytest.raises(ValueError, match='must'):
        validate_execution_retention(record, report, provenance)


@pytest.mark.parametrize('field,value', [('measured', True), ('measured', 1.0), ('minimum', 3.0)])
def test_reselected_installed_policy_integer_types_refuse(field: str, value: object) -> None:
    from tools.check_execution_retention import validate_execution_retention
    record, report, provenance = execution_inputs('installed-format-policy-2026-10-02')
    report['candidate-format-quality']['gate']['policyFailures'][0][field] = value
    claim = next(c for c in record['claimResults'] if c.get('recordedField') == '/candidate-format-quality/gate/policyFailures')
    claim['expectedValue'][0][field] = value
    with pytest.raises(ValueError, match='counts must be integers'):
        validate_execution_retention(record, report, provenance)
