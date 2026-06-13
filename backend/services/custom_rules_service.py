"""
Custom Alert Rules Service
Evaluates user-defined rules against captured packets in real-time.
"""

import ipaddress
import logging
import re
import time
from typing import Dict, List, Optional

logger = logging.getLogger('packet_peeper')

RULE_CONDITION_OPERATORS = {
    'eq': lambda a, b: a == b,
    'neq': lambda a, b: a != b,
    'gt': lambda a, b: a is not None and b is not None and float(a) > float(b),
    'gte': lambda a, b: a is not None and b is not None and float(a) >= float(b),
    'lt': lambda a, b: a is not None and b is not None and float(a) < float(b),
    'lte': lambda a, b: a is not None and b is not None and float(a) <= float(b),
    'contains': lambda a, b: str(b).lower() in str(a).lower(),
    'startswith': lambda a, b: str(a).lower().startswith(str(b).lower()),
    'endswith': lambda a, b: str(a).lower().endswith(str(b).lower()),
    'regex': lambda a, b: bool(re.search(str(b), str(a or ''))),
    'in': lambda a, b: a in (b if isinstance(b, list) else [b]),
    'not_in': lambda a, b: a not in (b if isinstance(b, list) else [b]),
    'cidr': lambda a, b: _ip_in_cidr(a, b),
}

RULE_LOGIC_OPERATORS = {'and', 'or'}

RULE_ACTIONS = {'alert', 'log', 'webhook', 'block'}


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except (ValueError, TypeError):
        return False


def _extract_packet_field(packet: Dict, field: str):
    field_map = {
        'src_ip': 'src_ip',
        'dst_ip': 'dst_ip',
        'src_port': 'src_port',
        'dst_port': 'dst_port',
        'protocol': 'protocol',
        'length': 'length',
        'service': 'service',
        'tcp_flags': 'tcp_flags',
        'payload': 'payload',
    }
    key = field_map.get(field, field)
    return packet.get(key)


def _evaluate_condition(packet: Dict, condition: Dict) -> bool:
    field = condition.get('field', '')
    operator = condition.get('operator', 'eq')
    value = condition.get('value')

    packet_value = _extract_packet_field(packet, field)
    op_func = RULE_CONDITION_OPERATORS.get(operator)
    if not op_func:
        logger.warning(f"[CustomRules] Unknown operator: {operator}")
        return False

    try:
        return op_func(packet_value, value)
    except Exception as e:
        logger.debug(f"[CustomRules] Condition eval error: {e}")
        return False


def evaluate_rule(packet: Dict, rule: Dict) -> bool:
    conditions = rule.get('conditions', {})
    if not conditions:
        return False

    logic = conditions.get('logic', 'and')
    checks = conditions.get('checks', [])

    if not checks:
        return False

    results = [_evaluate_condition(packet, c) for c in checks]

    if logic == 'or':
        return any(results)
    return all(results)


class CustomRulesEngine:
    def __init__(self, db_service=None):
        self.db_service = db_service
        self._rules: List[Dict] = []
        self._last_load: float = 0.0
        self._cooldowns: Dict[int, float] = {}
        self._load_interval: float = 30.0

    def reload_rules(self, force: bool = False) -> None:
        now = time.time()
        if not force and (now - self._last_load) < self._load_interval:
            return
        if self.db_service:
            try:
                self._rules = self.db_service.get_custom_rules(enabled_only=True)
                self._last_load = now
            except Exception as e:
                logger.error(f"[CustomRules] Error loading rules: {e}")

    def evaluate_packet(self, packet: Dict) -> List[Dict]:
        self.reload_rules()
        if not self._rules:
            return []

        triggered = []
        now = time.time()

        for rule in self._rules:
            if not rule.get('enabled', True):
                continue
            rule_id = rule.get('id')
            cooldown = rule.get('cooldown_seconds', 60)
            last_trigger = self._cooldowns.get(rule_id, 0)
            if now - last_trigger < cooldown:
                continue

            if evaluate_rule(packet, rule):
                self._cooldowns[rule_id] = now
                triggered.append(rule)
                if self.db_service:
                    try:
                        self.db_service.increment_rule_trigger(rule_id)
                    except Exception:
                        pass

        return triggered

    def get_rules(self) -> List[Dict]:
        return list(self._rules)

    def test_rule(self, rule: Dict, sample_packets: List[Dict]) -> Dict:
        matches = []
        for pkt in sample_packets:
            if evaluate_rule(pkt, rule):
                matches.append(pkt)
        return {
            'total_packets': len(sample_packets),
            'matching_packets': len(matches),
            'match_rate': round(len(matches) / max(len(sample_packets), 1) * 100, 2),
            'matches': matches[:10],
        }
