"""
Organizations Blueprint
Organization and member management endpoints.
"""

import re
import logging

from flask import Blueprint, request, jsonify, g

from config.config import ENABLE_AUTH
from services.auth_service import VALID_ROLES

import extensions as ext

bp = Blueprint('organizations', __name__, url_prefix='/api/organizations')
logger = logging.getLogger('packet_peeper')


def _require_auth():
    if not ENABLE_AUTH:
        return None
    if not g.get('current_user'):
        return jsonify({'error': 'Authentication required'}), 401
    return None


def _require_admin():
    if not ENABLE_AUTH:
        return None
    if g.get('current_role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    return None


def _slugify(name: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    return slug or 'org'


@bp.route('', methods=['GET'])
def list_organizations():
    check = _require_auth()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        if g.get('current_role') == 'admin':
            orgs = ext.db_service.get_all_organizations()
        else:
            user_id = g.get('current_user_id')
            orgs = ext.db_service.get_user_organizations(user_id) if user_id else []
        return jsonify({'organizations': orgs, 'total': len(orgs)})
    except Exception as e:
        logger.error(f"Error listing organizations: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('', methods=['POST'])
def create_organization():
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        if not name or len(name) < 2:
            return jsonify({'error': 'Organization name is required (min 2 chars)'}), 400

        slug = (data.get('slug') or '').strip() or _slugify(name)
        if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', slug):
            return jsonify({'error': 'Slug must be lowercase alphanumeric with dashes'}), 400

        existing = ext.db_service.get_organization_by_slug(slug)
        if existing:
            return jsonify({'error': 'Organization slug already exists'}), 409

        org_data = {
            'name': name,
            'slug': slug,
            'settings': data.get('settings', {}),
        }
        org = ext.db_service.create_organization(org_data)
        if not org:
            return jsonify({'error': 'Failed to create organization'}), 500

        creator_id = g.get('current_user_id')
        if creator_id:
            ext.db_service.add_org_member(org['id'], creator_id, role='admin')
            ext.db_service.update_user(g.current_user, {'default_org_id': org['id']})

        ext.add_log('info', 'Organizations', f'Organization created: {name} ({slug})')
        return jsonify({'organization': org}), 201
    except Exception as e:
        logger.error(f"Error creating organization: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>', methods=['GET'])
def get_organization(org_id):
    check = _require_auth()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        return jsonify({'organization': org})
    except Exception as e:
        logger.error(f"Error getting organization: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>', methods=['PUT'])
def update_organization(org_id):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        updates = {}
        if 'name' in data:
            updates['name'] = data['name'].strip()
        if 'slug' in data:
            slug = data['slug'].strip()
            if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', slug):
                return jsonify({'error': 'Slug must be lowercase alphanumeric with dashes'}), 400
            existing = ext.db_service.get_organization_by_slug(slug)
            if existing and existing['id'] != org_id:
                return jsonify({'error': 'Slug already in use'}), 409
            updates['slug'] = slug
        if 'is_active' in data:
            updates['is_active'] = bool(data['is_active'])
        if 'settings' in data:
            updates['settings'] = data['settings']

        if not updates:
            return jsonify({'error': 'No valid fields to update'}), 400

        success = ext.db_service.update_organization(org_id, updates)
        if success:
            ext.add_log('info', 'Organizations', f'Organization updated: {org_id}')
            updated = ext.db_service.get_organization(org_id)
            return jsonify({'message': 'Organization updated', 'organization': updated})
        return jsonify({'error': 'Failed to update organization'}), 500
    except Exception as e:
        logger.error(f"Error updating organization: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>', methods=['DELETE'])
def delete_organization(org_id):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        success = ext.db_service.delete_organization(org_id)
        if success:
            ext.add_log('info', 'Organizations', f'Organization deleted: {org_id}')
            return jsonify({'message': 'Organization deleted'})
        return jsonify({'error': 'Failed to delete organization'}), 500
    except Exception as e:
        logger.error(f"Error deleting organization: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>/members', methods=['GET'])
def list_org_members(org_id):
    check = _require_auth()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        members = ext.db_service.get_org_members(org_id)
        return jsonify({'members': members, 'total': len(members)})
    except Exception as e:
        logger.error(f"Error listing org members: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>/members', methods=['POST'])
def add_org_member(org_id):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        role = (data.get('role') or 'viewer').strip().lower()

        if not username:
            return jsonify({'error': 'Username is required'}), 400
        if role not in VALID_ROLES:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(sorted(VALID_ROLES))}'}), 400

        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        user = ext.db_service.get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        member = ext.db_service.add_org_member(org_id, user['id'], role=role)
        if not member:
            return jsonify({'error': 'Failed to add member'}), 500

        ext.add_log('info', 'Organizations', f'{username} added to org {org_id} as {role}')
        return jsonify({'member': member}), 201
    except Exception as e:
        logger.error(f"Error adding org member: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>/members/<int:user_id>', methods=['DELETE'])
def remove_org_member(org_id, user_id):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        success = ext.db_service.remove_org_member(org_id, user_id)
        if success:
            ext.add_log('info', 'Organizations', f'User {user_id} removed from org {org_id}')
            return jsonify({'message': 'Member removed'})
        return jsonify({'error': 'Member not found'}), 404
    except Exception as e:
        logger.error(f"Error removing org member: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:org_id>/members/<int:user_id>/role', methods=['PUT'])
def update_org_member_role(org_id, user_id):
    check = _require_admin()
    if check:
        return check
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json(silent=True) or {}
        new_role = (data.get('role') or '').strip().lower()
        if new_role not in VALID_ROLES:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(sorted(VALID_ROLES))}'}), 400

        org = ext.db_service.get_organization(org_id)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        success = ext.db_service.update_org_member_role(org_id, user_id, new_role)
        if success:
            ext.add_log('info', 'Organizations', f'Member {user_id} role updated to {new_role} in org {org_id}')
            return jsonify({'message': f'Role updated to {new_role}'})
        return jsonify({'error': 'Member not found in organization'}), 404
    except Exception as e:
        logger.error(f"Error updating org member role: {str(e)}")
        return jsonify({'error': str(e)}), 500
