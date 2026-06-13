"""
Custom Alert Rules Tests
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.custom_rules_service import evaluate_rule, CustomRulesEngine


def test_evaluate_simple_eq():
    packet = {'src_ip': '192.168.1.1', 'dst_port': 80, 'protocol': 'TCP'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'dst_port', 'operator': 'eq', 'value': 80}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_simple_neq():
    packet = {'src_ip': '192.168.1.1', 'dst_port': 443, 'protocol': 'TCP'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'dst_port', 'operator': 'neq', 'value': 80}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_gt():
    packet = {'length': 1500}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'length', 'operator': 'gt', 'value': 1000}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_contains():
    packet = {'service': 'YouTube Streaming'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'service', 'operator': 'contains', 'value': 'youtube'}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_cidr():
    packet = {'src_ip': '192.168.1.50'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'src_ip', 'operator': 'cidr', 'value': '192.168.1.0/24'}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_cidr_no_match():
    packet = {'src_ip': '10.0.0.1'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'src_ip', 'operator': 'cidr', 'value': '192.168.1.0/24'}],
        },
    }
    assert evaluate_rule(packet, rule) is False


def test_evaluate_and_logic():
    packet = {'src_ip': '10.0.0.1', 'dst_port': 22, 'protocol': 'TCP'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [
                {'field': 'dst_port', 'operator': 'eq', 'value': 22},
                {'field': 'protocol', 'operator': 'eq', 'value': 'TCP'},
            ],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_and_one_fails():
    packet = {'src_ip': '10.0.0.1', 'dst_port': 22, 'protocol': 'UDP'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [
                {'field': 'dst_port', 'operator': 'eq', 'value': 22},
                {'field': 'protocol', 'operator': 'eq', 'value': 'TCP'},
            ],
        },
    }
    assert evaluate_rule(packet, rule) is False


def test_evaluate_or_logic():
    packet = {'dst_port': 80}
    rule = {
        'conditions': {
            'logic': 'or',
            'checks': [
                {'field': 'dst_port', 'operator': 'eq', 'value': 80},
                {'field': 'dst_port', 'operator': 'eq', 'value': 443},
            ],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_or_all_fail():
    packet = {'dst_port': 22}
    rule = {
        'conditions': {
            'logic': 'or',
            'checks': [
                {'field': 'dst_port', 'operator': 'eq', 'value': 80},
                {'field': 'dst_port', 'operator': 'eq', 'value': 443},
            ],
        },
    }
    assert evaluate_rule(packet, rule) is False


def test_evaluate_in_operator():
    packet = {'dst_port': 443}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'dst_port', 'operator': 'in', 'value': [80, 443, 8080]}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_regex():
    packet = {'src_ip': '10.0.5.123'}
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'src_ip', 'operator': 'regex', 'value': r'^10\.0\.\d+\.\d+$'}],
        },
    }
    assert evaluate_rule(packet, rule) is True


def test_evaluate_empty_conditions():
    packet = {'src_ip': '10.0.0.1'}
    rule = {'conditions': {}}
    assert evaluate_rule(packet, rule) is False


def test_engine_cooldown():
    engine = CustomRulesEngine(db_service=None)
    engine._rules = [
        {
            'id': 1,
            'name': 'test',
            'enabled': True,
            'severity': 'medium',
            'cooldown_seconds': 60,
            'conditions': {
                'logic': 'and',
                'checks': [{'field': 'dst_port', 'operator': 'eq', 'value': 80}],
            },
        },
    ]
    engine._last_load = 9999999999

    pkt = {'dst_port': 80}
    triggered = engine.evaluate_packet(pkt)
    assert len(triggered) == 1

    triggered2 = engine.evaluate_packet(pkt)
    assert len(triggered2) == 0


def test_engine_disabled_rule():
    engine = CustomRulesEngine(db_service=None)
    engine._rules = [
        {
            'id': 1,
            'name': 'test',
            'enabled': False,
            'severity': 'medium',
            'cooldown_seconds': 0,
            'conditions': {
                'logic': 'and',
                'checks': [{'field': 'dst_port', 'operator': 'eq', 'value': 80}],
            },
        },
    ]
    engine._last_load = 9999999999

    pkt = {'dst_port': 80}
    triggered = engine.evaluate_packet(pkt)
    assert len(triggered) == 0


def test_test_rule():
    engine = CustomRulesEngine(db_service=None)
    rule = {
        'conditions': {
            'logic': 'and',
            'checks': [{'field': 'dst_port', 'operator': 'eq', 'value': 80}],
        },
    }
    packets = [
        {'dst_port': 80},
        {'dst_port': 443},
        {'dst_port': 80},
        {'dst_port': 22},
    ]
    result = engine.test_rule(rule, packets)
    assert result['total_packets'] == 4
    assert result['matching_packets'] == 2
    assert result['match_rate'] == 50.0
