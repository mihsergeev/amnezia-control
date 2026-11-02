import copy
import json
from types import SimpleNamespace

import pytest

from app import cascade_underlay, sshops


def responses():
    return {
        ('docker', 'inspect', 'acontrol-awg-link'): [{'Config': {'Labels': {'acontrol-awg-link-v1': ''}}, 'State': {'Running': True}}],
        ('ip', '-j', '-d', 'link', 'show', 'acgre'): [{'flags': ['UP'], 'linkinfo': {'info_kind': 'gre', 'info_data': {'local': '10.199.2.1', 'remote': '10.199.2.2', 'link': 'acawg'}}}],
        ('ip', '-j', 'addr', 'show', 'acawg'): [{'ifindex': 9, 'flags': ['UP'], 'addr_info': [{'local': '10.199.2.1'}]}],
        ('ip', '-j', 'route', 'show', 'table', '243'): [{'dst': '10.199.2.2', 'dev': 'acawg'}],
        ('ip', '-j', 'rule', 'show'): [{'priority': 1006, 'dst': '10.199.2.2', 'ipproto': 'gre', 'table': '243'}],
        ('docker', 'exec', 'acontrol-awg-link', 'awg', 'show', 'acawg', 'latest-handshakes'): 'peer-a\t999990',
        ('docker', 'exec', 'acontrol-awg-link', 'awg', 'show', 'acawg', 'allowed-ips'): 'peer-a\t10.199.2.2/32',
        ('docker', 'exec', 'acontrol-awg-link', 'awg', 'show', 'acawg', 'endpoints'): 'peer-a\t203.0.113.9:47225',
    }


def run_probe(monkeypatch, capsys, values):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        assert kwargs['timeout'] == 3
        value = values[tuple(args)]
        if isinstance(value, Exception):
            raise value
        return SimpleNamespace(returncode=0, stdout=value if isinstance(value, str) else json.dumps(value))

    monkeypatch.setattr('subprocess.run', fake_run)
    monkeypatch.setattr('time.time', lambda: 1000000)
    exec(compile(cascade_underlay.PROBE_PY, '<underlay-probe>', 'exec'), {})
    out = capsys.readouterr().out
    assert all('dump' not in c and 'private-key' not in c and 'preshared-keys' not in c for c in calls)
    result = sshops._parse_check_output('HOST=vpn-a\n' + out)
    assert result.containers == []
    return result.cascade_link


def test_live_binding_peer_and_route_prove_encryption(monkeypatch, capsys):
    result = run_probe(monkeypatch, capsys, responses())
    assert result == {'transport': 'awg', 'encrypted': True, 'tunnel': 'acgre',
                      'public_remote': '203.0.113.9', 'handshake_age': 10, 'healthy': True}


@pytest.mark.parametrize('change', ['foreign', 'stopped', 'binding', 'local', 'default_peer', 'peer_mismatch', 'never', 'route', 'policy', 'gre_down', 'awg_down', 'unavailable'])
def test_installed_interface_or_stale_handshake_is_not_proof(monkeypatch, capsys, change):
    values = responses()
    inspect = values[('docker', 'inspect', 'acontrol-awg-link')][0]
    gre = values[('ip', '-j', '-d', 'link', 'show', 'acgre')][0]
    awg = values[('ip', '-j', 'addr', 'show', 'acawg')][0]
    key = ('docker', 'exec', 'acontrol-awg-link', 'awg', 'show', 'acawg')
    if change == 'foreign': inspect['Config']['Labels'] = {}
    if change == 'stopped': inspect['State']['Running'] = False
    if change == 'binding': gre['linkinfo']['info_data']['link'] = 'eth0'
    if change == 'local': awg['addr_info'][0]['local'] = '10.199.3.1'
    if change == 'default_peer': values[key + ('allowed-ips',)] = 'peer-a\t0.0.0.0/0'
    if change == 'peer_mismatch': values[key + ('endpoints',)] = 'peer-b\t203.0.113.9:47225'
    if change == 'never': values[key + ('latest-handshakes',)] = 'peer-a\t0'
    if change == 'route': values[('ip', '-j', 'route', 'show', 'table', '243')][0]['dev'] = 'eth0'
    if change == 'policy': values[('ip', '-j', 'rule', 'show')] = []
    if change == 'gre_down': gre['flags'] = []
    if change == 'awg_down': awg['flags'] = []
    if change == 'unavailable': values[key + ('latest-handshakes',)] = TimeoutError()
    assert run_probe(monkeypatch, capsys, values).get('encrypted') is not True


def test_stale_link_keeps_encryption_mode_but_is_not_healthy(monkeypatch, capsys):
    values = responses()
    key = ('docker', 'exec', 'acontrol-awg-link', 'awg', 'show', 'acawg', 'latest-handshakes')
    values[key] = 'peer-a\t999800'
    result = run_probe(monkeypatch, capsys, values)
    assert result['encrypted'] is True
    assert result['healthy'] is False
    assert result['handshake_age'] == 200


def test_probe_discards_extra_fields_and_invalid_evidence():
    value = {'transport': 'awg', 'encrypted': True, 'tunnel': 'acgre',
             'public_remote': '203.0.113.9', 'handshake_age': 10, 'private_key': 'never-export'}
    assert 'private_key' not in cascade_underlay.parse_probe(json.dumps(value))
    for field, replacement in [('encrypted', 'true'),
                               ('handshake_age', None), ('handshake_age', True),
                               ('public_remote', 'invalid'), ('transport', 'gre')]:
        changed = copy.deepcopy(value)
        changed[field] = replacement
        assert cascade_underlay.parse_probe(json.dumps(changed)) == {}
    assert cascade_underlay.parse_probe('[]') == {}
    assert cascade_underlay.parse_probe('{broken') == {}
