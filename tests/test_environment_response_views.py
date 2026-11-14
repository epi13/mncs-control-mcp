"""Environment response navigation preserves typed selection and admission."""
import json

import pytest

from mncs_control_mcp import local_environment_mcp
from mncs_control_mcp.environment_rpc import (
    EnvironmentRPCServer,
    _requires_selected_session_for_mutation,
)
from mncs_control_mcp.local_environment_mcp import LocalEnvironmentMCP, _build_argv, _ProjectContext


def context():
    value = _ProjectContext('grant', '/workspace/mncs-environment')
    value.selected_session_id = 'ses_selected'
    return value


@pytest.mark.parametrize('arguments, expected', [
    ({'section': 'workspace', 'compact': True}, ['--section=workspace', '--compact']),
    ({'section': 'events'}, ['--section=events']),
    ({'compact': True}, ['--compact']),
])
def test_inspection_view_maps_to_fixed_selected_session(arguments, expected):
    argv, uses_session = _build_argv('inspect', arguments, context(), 'mncs-environment')
    assert argv == ['inspect', 'ses_selected', *expected] and uses_session
    assert EnvironmentRPCServer._cli_positionals(argv, 0) == [(1, 'ses_selected')]
    assert EnvironmentRPCServer._read_only_operation_identity(argv) == 'session.inspect'
    assert not _requires_selected_session_for_mutation('inspect', argv)


def test_summary_and_detail_selectors_stay_read_only():
    for arguments in ({'summary': True, 'limit': 25, 'offset': 50}, {'capability': 'provider:action'}):
        argv, selected = _build_argv('capabilities', arguments, context(), 'mncs-environment')
        assert selected
        assert EnvironmentRPCServer._cli_positionals(argv, 0) == [(1, 'ses_selected')]
        assert EnvironmentRPCServer._read_only_operation_identity(argv) == 'session.capabilities'
        assert not _requires_selected_session_for_mutation('capabilities', argv)
    argv, _ = _build_argv('capabilities', {'preflight': 'provider:action'}, context(), 'mncs-environment')
    assert _requires_selected_session_for_mutation('capabilities', argv)


@pytest.mark.parametrize('operation, arguments', [
    ('inspect', {'section': '../outside'}), ('inspect', {'compact': 'yes'}),
    ('inspect', {'argv': ['arbitrary']}), ('inspect', {'session_id': 'ses_other', 'compact': True}),
    ('capabilities', {'summary': 'yes'}), ('capabilities', {'summary': True, 'limit': 101}),
    ('capabilities', {'summary': True, 'offset': -1}), ('capabilities', {'summary': True, 'limit': True}),
    ('capabilities', {'summary': True, 'capability': 'provider:action'}),
    ('capabilities', {'capability': '--invoke'}), ('capabilities', {'offset': 10}),
])
def test_views_cannot_supply_arbitrary_arguments_or_other_sessions(operation, arguments):
    with pytest.raises(ValueError):
        _build_argv(operation, arguments, context(), 'mncs-environment')


def test_context_preserves_orientation_attention_and_legacy_capability_list():
    payload = {'session_id': 'ses_selected', 'configuration': {'source': 'owner-definition'},
        'observation': 'recorded-session', 'continuation': {'completion_recovery': {'state': 'pending'}},
        'actions': {'workspace': {'argv': ['inspect', 'ses_selected', '--section', 'workspace', '--compact']}},
        'next_commands': ['capabilities ses_selected --summary'], 'project_count': 90, 'projects_truncated': True,
        'capabilities': {'available': [{'capability': 'provider:action', 'binding_id': 'cap_action'}],
            'available_count': 25, 'unavailable_count': 3, 'unknown_count': 7, 'truncated': True,
            'availability_attention': {'unknown_reason_code_counts': [{'code': 'provider-invocation-undeclared', 'count': 7}]}},
        'authority': {'claim_required_actions': ['write']},
        'doctor': {'unavailable': {'count': 3}, 'remaining_truncated': True}}
    result = LocalEnvironmentMCP._compact_context(payload)
    for key in ('configuration', 'observation', 'continuation', 'actions', 'next_commands', 'project_count', 'projects_truncated'):
        assert result[key] == payload[key]
    assert result['capabilities']['available'] == ['provider:action']
    assert result['capabilities']['count'] == 1  # retain existing listed-count contract
    assert result['capabilities']['available_count'] == 25
    assert result['capabilities']['unknown_count'] == 7
    assert result['capabilities']['availability_attention'] == payload['capabilities']['availability_attention']
    assert result['capabilities']['available_bindings'] == payload['capabilities']['available']
    assert result['doctor'] == payload['doctor']
    assert result['authority'] == payload['authority']


def test_explicit_details_pass_through_without_second_compaction(monkeypatch):
    selected = context()
    bridge = LocalEnvironmentMCP()
    monkeypatch.setattr(bridge, '_context', lambda *_args: selected)
    monkeypatch.setattr(bridge, '_select_session', lambda *_args, **_kwargs: None)
    document = {'session_id': 'ses_selected', 'representation': 'shared-json-pointers',
                'workspace': {'repositories': [{'worktrees': [{}]}, {'worktrees': {'$ref': '#/workspace/repositories/0/worktrees'}}]}}
    monkeypatch.setattr(local_environment_mcp, '_rpc', lambda *_args: {
        'ok': True, 'result': {'exit_code': 0, 'stdout': json.dumps(document)}})
    result = bridge.invoke('mncs-environment', 'inspect', {'section': 'workspace', 'compact': True})
    assert result["ok"] and result["result"] == document, result


def test_new_binding_detail_is_structured_while_legacy_list_remains_compatible(monkeypatch):
    selected = context()
    bridge = LocalEnvironmentMCP()
    monkeypatch.setattr(bridge, '_context', lambda *_args: selected)
    monkeypatch.setattr(bridge, '_select_session', lambda *_args, **_kwargs: None)
    bindings = [{'binding_id': 'cap_selected', 'availability': {'status': 'unknown'},
                 'provenance': {'source_ref': 'owner-manifest', 'checkout': {'head': 'a' * 40}}}]
    stdout = json.dumps(bindings, indent=2)
    monkeypatch.setattr(local_environment_mcp, '_rpc', lambda *_args: {
        'ok': True, 'result': {'exit_code': 0, 'stdout': stdout}})
    detail = bridge.invoke('mncs-environment', 'capabilities', {'capability': 'cap_selected'})
    assert detail['result'] == bindings
    legacy = bridge.invoke('mncs-environment', 'capabilities', {})
    assert legacy['result'] == stdout
