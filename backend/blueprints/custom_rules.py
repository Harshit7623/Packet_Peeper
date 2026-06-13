"""
Custom Alert Rules API
CRUD + test endpoints for user-defined detection rules.
"""

from flask import Blueprint, request, jsonify, g
import extensions as ext

custom_rules_bp = Blueprint('custom_rules', __name__, url_prefix='/api/custom-rules')

_custom_rules_engine = None


def _get_engine():
    global _custom_rules_engine
    if _custom_rules_engine is None:
        from services.custom_rules_service import CustomRulesEngine
        _custom_rules_engine = CustomRulesEngine(db_service=ext.db_service)
    return _custom_rules_engine


@custom_rules_bp.route('', methods=['GET'])
def list_rules():
    org_id = getattr(g, 'org_id', None) if hasattr(g, 'org_id') else None
    rules = ext.db_service.get_custom_rules(org_id=org_id) if ext.db_service else []
    return jsonify({'rules': rules, 'total': len(rules)})


@custom_rules_bp.route('/<int:rule_id>', methods=['GET'])
def get_rule(rule_id):
    rule = ext.db_service.get_custom_rule(rule_id) if ext.db_service else None
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    return jsonify(rule)


@custom_rules_bp.route('', methods=['POST'])
def create_rule():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    conditions = data.get('conditions')
    if not name:
        return jsonify({'error': 'Rule name is required'}), 400
    if not conditions:
        return jsonify({'error': 'Conditions are required'}), 400

    rule_data = {
        'name': name,
        'description': data.get('description', ''),
        'enabled': data.get('enabled', True),
        'severity': data.get('severity', 'medium'),
        'conditions': conditions,
        'action': data.get('action', 'alert'),
        'action_config': data.get('action_config', {}),
        'cooldown_seconds': data.get('cooldown_seconds', 60),
        'created_by': getattr(g, 'current_user', None),
        'org_id': getattr(g, 'org_id', None) if hasattr(g, 'org_id') else None,
    }

    result = ext.db_service.create_custom_rule(rule_data) if ext.db_service else None
    if not result:
        return jsonify({'error': 'Failed to create rule'}), 500

    _get_engine().reload_rules(force=True)
    ext.add_log('info', 'CustomRules', f"Created rule: {name}")
    return jsonify(result), 201


@custom_rules_bp.route('/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    existing = ext.db_service.get_custom_rule(rule_id) if ext.db_service else None
    if not existing:
        return jsonify({'error': 'Rule not found'}), 404

    data = request.get_json(silent=True) or {}
    allowed_fields = {'name', 'description', 'enabled', 'severity', 'conditions',
                       'action', 'action_config', 'cooldown_seconds'}
    update_data = {k: v for k, v in data.items() if k in allowed_fields}

    result = ext.db_service.update_custom_rule(rule_id, update_data) if ext.db_service else None
    if not result:
        return jsonify({'error': 'Failed to update rule'}), 500

    _get_engine().reload_rules(force=True)
    return jsonify(result)


@custom_rules_bp.route('/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    success = ext.db_service.delete_custom_rule(rule_id) if ext.db_service else False
    if not success:
        return jsonify({'error': 'Rule not found'}), 404

    _get_engine().reload_rules(force=True)
    ext.add_log('info', 'CustomRules', f"Deleted rule ID {rule_id}")
    return jsonify({'message': 'Rule deleted'})


@custom_rules_bp.route('/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule(rule_id):
    existing = ext.db_service.get_custom_rule(rule_id) if ext.db_service else None
    if not existing:
        return jsonify({'error': 'Rule not found'}), 404

    new_enabled = not existing.get('enabled', True)
    result = ext.db_service.update_custom_rule(rule_id, {'enabled': new_enabled}) if ext.db_service else None
    if not result:
        return jsonify({'error': 'Failed to toggle rule'}), 500

    _get_engine().reload_rules(force=True)
    return jsonify(result)


@custom_rules_bp.route('/test', methods=['POST'])
def test_rule():
    data = request.get_json(silent=True) or {}
    rule_def = {
        'conditions': data.get('conditions', {}),
    }
    sample_packets = data.get('sample_packets', [])
    if not sample_packets:
        recent = list(ext.alerts[-50:]) if ext.alerts else []
        packets = []
        if ext.sniffer and hasattr(ext.sniffer, '_packet_buffer'):
            packets = list(getattr(ext.sniffer, '_packet_buffer', [])[-100:])
        sample_packets = packets or recent or []

    from services.custom_rules_service import evaluate_rule
    matches = []
    for pkt in sample_packets:
        if evaluate_rule(pkt, rule_def):
            matches.append(pkt)

    return jsonify({
        'total_packets': len(sample_packets),
        'matching_packets': len(matches),
        'match_rate': round(len(matches) / max(len(sample_packets), 1) * 100, 2),
        'matches': matches[:10],
    })


@custom_rules_bp.route('/fields', methods=['GET'])
def get_available_fields():
    from services.custom_rules_service import RULE_CONDITION_OPERATORS
    fields = [
        {'name': 'src_ip', 'label': 'Source IP', 'type': 'string', 'operators': ['eq', 'neq', 'contains', 'regex', 'cidr', 'in', 'not_in']},
        {'name': 'dst_ip', 'label': 'Destination IP', 'type': 'string', 'operators': ['eq', 'neq', 'contains', 'regex', 'cidr', 'in', 'not_in']},
        {'name': 'src_port', 'label': 'Source Port', 'type': 'number', 'operators': ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in']},
        {'name': 'dst_port', 'label': 'Destination Port', 'type': 'number', 'operators': ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in']},
        {'name': 'protocol', 'label': 'Protocol', 'type': 'string', 'operators': ['eq', 'neq', 'contains', 'in', 'not_in']},
        {'name': 'length', 'label': 'Packet Length', 'type': 'number', 'operators': ['eq', 'neq', 'gt', 'gte', 'lt', 'lte']},
        {'name': 'service', 'label': 'Service', 'type': 'string', 'operators': ['eq', 'neq', 'contains', 'regex', 'in', 'not_in']},
        {'name': 'tcp_flags', 'label': 'TCP Flags', 'type': 'number', 'operators': ['eq', 'neq', 'gt', 'gte', 'lt', 'lte']},
        {'name': 'payload', 'label': 'Payload', 'type': 'string', 'operators': ['contains', 'regex', 'startswith', 'endswith']},
    ]
    operators = [{'name': k, 'label': k} for k in RULE_CONDITION_OPERATORS.keys()]
    return jsonify({'fields': fields, 'operators': operators})
