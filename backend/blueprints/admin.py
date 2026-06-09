"""
Admin Blueprint
User management, role assignment, and org membership administration.
"""

import logging

from flask import Blueprint, request, jsonify, g

from config.config import ENABLE_AUTH
from services.auth_service import VALID_ROLES

import extensions as ext

bp = Blueprint('admin', __name__, url_prefix='/api/admin')
logger = logging.getLogger('packet_peeper')


def _require_admin():
    if not ENABLE_AUTH:
        return None
    if not g.get('current_role') or g.current_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    return None


@bp.route('/users', methods=['GET'])
def list_users():
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        users = ext.db_service.get_all_users()
        return jsonify({'users': users, 'total': len(users)})
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>', methods=['GET'])
def get_user(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        user.pop('password_hash', None)
        return jsonify({'user': user})
    except Exception as e:
        logger.error(f"Error getting user: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>/role', methods=['PUT'])
def update_user_role(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        new_role = data.get('role', '').strip().lower()
        if new_role not in VALID_ROLES:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(sorted(VALID_ROLES))}'}), 400

        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('username') == g.get('current_user'):
            return jsonify({'error': 'Cannot change your own role'}), 400

        success = ext.db_service.update_user(username, {'role': new_role})
        if success:
            ext.add_log('info', 'Admin', f'Role changed for {username}: {new_role}')
            return jsonify({'message': f'Role updated to {new_role}', 'username': username, 'role': new_role})
        return jsonify({'error': 'Failed to update role'}), 500
    except Exception as e:
        logger.error(f"Error updating user role: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>/active', methods=['PUT'])
def toggle_user_active(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        is_active = data.get('is_active', True)

        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('username') == g.get('current_user'):
            return jsonify({'error': 'Cannot change your own active status'}), 400

        success = ext.db_service.update_user(username, {'is_active': is_active})
        if success:
            action = 'enabled' if is_active else 'disabled'
            ext.add_log('info', 'Admin', f'Account {action}: {username}')
            if not is_active:
                ext.db_service.delete_user_sessions(user.get('id'))
            return jsonify({'message': f'Account {action}', 'username': username, 'is_active': is_active})
        return jsonify({'error': 'Failed to update active status'}), 500
    except Exception as e:
        logger.error(f"Error toggling user active: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>', methods=['DELETE'])
def delete_user(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.get('username') == g.get('current_user'):
            return jsonify({'error': 'Cannot delete your own account'}), 400

        ext.db_service.delete_user_sessions(user.get('id'))
        success = ext.db_service.delete_user(username)
        if success:
            ext.add_log('info', 'Admin', f'User deleted: {username}')
            return jsonify({'message': f'User {username} deleted'})
        return jsonify({'error': 'Failed to delete user'}), 500
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>/org', methods=['PUT'])
def set_user_org(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        org_id = data.get('org_id')

        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if org_id is not None:
            org = ext.db_service.get_organization(org_id)
            if not org:
                return jsonify({'error': 'Organization not found'}), 404

        success = ext.db_service.update_user(username, {'default_org_id': org_id})
        if success:
            ext.add_log('info', 'Admin', f'Default org set for {username}: {org_id}')
            return jsonify({'message': 'Default organization updated', 'username': username, 'default_org_id': org_id})
        return jsonify({'error': 'Failed to update default org'}), 500
    except Exception as e:
        logger.error(f"Error setting user org: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/users/<username>/sessions', methods=['DELETE'])
def revoke_user_sessions(username):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        deleted = ext.db_service.delete_user_sessions(user.get('id'))
        ext.add_log('info', 'Admin', f'Revoked {deleted} sessions for {username}')
        return jsonify({'message': f'{deleted} sessions revoked', 'username': username})
    except Exception as e:
        logger.error(f"Error revoking user sessions: {str(e)}")
        return jsonify({'error': str(e)}), 500
