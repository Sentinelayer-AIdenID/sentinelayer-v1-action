import pytest

from omargate.analyze.typesafe_review import build_inventory
from omargate.redaction import redact_secret_source, sanitize_public_error


@pytest.mark.parametrize('source', [
    'api_key: ${{ secrets.OPENAI_API_KEY }}\n',
    '  OPENAI_API_KEY: "${{ secrets.OPENAI_API_KEY }}"\n',
    "  typesafe_api_key: '${{secrets.TYPESAFE_API_KEY}}' # symbolic input\n",
    '  github_token: ${{ secrets.GITHUB_TOKEN }}\n',
    '+  api_key: ${{ secrets.OPENAI_API_KEY }}\n',
    '-  api_key: ${{ secrets.OLD_API_KEY }}\n',
])
def test_whole_symbolic_secret_references_are_source_not_credential_bytes(tmp_path, source):
    path = tmp_path / 'workflow.yml'
    path.write_bytes(source.encode('utf-8'))
    inventory = build_inventory(repo_root=tmp_path, ingest={'files': [{'path': path.name}]},
                                changed_files=[path.name], scan_mode='pr-diff', max_candidates=50)
    safe, changed = redact_secret_source(source, file_path=path.name)
    assert safe == source and changed is False
    assert sanitize_public_error(safe) == source
    state = inventory.candidates[0].state()
    assert state['evidence'] == source
    assert state['evidence_redacted'] is False


@pytest.mark.parametrize('source', [
    'api_key: ${{ secrets.KEY }}literal-credential\n',
    'api_key: literal-credential${{ secrets.KEY }}\n',
    'api_key: ${{ secrets.KEY || "literal-credential" }}\n',
    'api_key: ${{ secrets[name] }}\n',
    'api_key: "${{ secrets.KEY }}\n',
    'api_key: ${{ secrets.KEY }} # password=literal-credential\n',
    'api_key: literal-credential # ${{ secrets.KEY }}\n',
    'api_key: ${{ secrets.KEY }}; token=literal-credential\n',
])
def test_mixed_dynamic_malformed_or_comment_credentials_stay_excluded(source):
    safe, changed = redact_secret_source(source, file_path='workflow.yml')
    assert changed is True
    assert 'literal-credential' not in safe
    assert safe == '[secret-bearing source excluded]\n'


def test_symbolic_reference_never_exempts_a_sensitive_file_or_pem_material():
    source = 'api_key: ${{ secrets.KEY }}\n'
    assert redact_secret_source(source, file_path='.env')[1] is True
    marker = ''.join(('-----', 'BEGIN PRIVATE KEY-----'))
    assert redact_secret_source(source.rstrip() + ' # ' + marker + '\n')[1] is True


def test_verified_diff_keeps_symbolic_reference_lines_and_head_hashes(tmp_path):
    from omargate.analyze.typesafe_state import build_typed_context
    source = 'api_key: ${{ secrets.OPENAI_API_KEY }}\n'
    (tmp_path / 'workflow.yml').write_bytes(source.encode())
    ingest = {'files': [{'path': 'workflow.yml', 'language': 'yaml'}]}
    inventory = build_inventory(repo_root=tmp_path, ingest=ingest, changed_files=['workflow.yml'],
                                scan_mode='pr-diff', max_candidates=50)
    diff = 'diff --git a/workflow.yml b/workflow.yml\n--- /dev/null\n+++ b/workflow.yml\n@@ -0,0 +1 @@\n+' + source
    context = build_typed_context(repo_root=tmp_path, inventory=inventory, diff_content=diff,
                                 ingest=ingest, deterministic_findings=[])
    hunk = context['candidate_context'][inventory.candidates[0].candidate_id]['diff_hunks'][0]
    assert hunk['source_redacted'] is False
    assert '+' + source.rstrip() in hunk['diff_hunk']
