"""
RBAC Enforcement Tests
Verifies role-based access control rules defined in RBAC_ENDPOINT_RULES.
Destructive tests (clear_all, clear_alerts, clear_logs) run last to avoid
invalidating operator sessions needed by earlier tests.
"""

import pytest


def _auth_header(token):
    return {'Authorization': f'Bearer {token}'}


class TestRBACEndpoints:
    """Verify that endpoint RBAC rules are enforced properly."""

    admin_token = None
    operator_token = None
    admin_username = None
    admin_password = None
    operator_username = None
    org_id = None
    _registered = False

    @pytest.fixture(autouse=True)
    def setup(self, client, auth_user_payload):
        """Register admin + operator once per session."""
        if TestRBACEndpoints._registered:
            self.client = client
            return

        resp = client.post('/api/auth/register', json=auth_user_payload)
        # If user already exists from another test class, pick a different name
        if resp.status_code == 409:
            import uuid
            alt_payload = dict(auth_user_payload)
            alt_payload['username'] = f"admin_{uuid.uuid4().hex[:8]}"
            alt_payload['email'] = f"{alt_payload['username']}@example.com"
            resp = client.post('/api/auth/register', json=alt_payload)
        assert resp.status_code == 201, f"Admin registration failed: {resp.get_json()}"
        TestRBACEndpoints.admin_username = resp.get_json()['user']['username']
        TestRBACEndpoints.admin_password = auth_user_payload['password']

        # Ensure admin role — update via DB if first-user privilege wasn't ours
        if resp.get_json().get('user', {}).get('role') != 'admin':
            import app
            app.ext.db_service.update_user(
                TestRBACEndpoints.admin_username,
                {'role': 'admin', 'is_admin': True},
            )

        admin_login = client.post('/api/auth/login', json={
            'username': TestRBACEndpoints.admin_username,
            'password': TestRBACEndpoints.admin_password,
        })
        assert admin_login.status_code == 200, f"Admin login failed: {admin_login.get_json()}"
        TestRBACEndpoints.admin_token = admin_login.get_json()['token']

        op_payload = {
            'username': f'op_{auth_user_payload["username"]}',
            'email': f'op_{auth_user_payload["email"]}',
            'password': 'StrongPass!123',
            'password_confirm': 'StrongPass!123',
        }
        resp = client.post('/api/auth/register', json=op_payload)
        assert resp.status_code == 201, f"Operator registration failed: {resp.get_json()}"
        TestRBACEndpoints.operator_username = op_payload['username']

        op_login = client.post('/api/auth/login', json={
            'username': op_payload['username'],
            'password': op_payload['password'],
        })
        assert op_login.status_code == 200, f"Operator login failed: {op_login.get_json()}"
        TestRBACEndpoints.operator_token = op_login.get_json()['token']
        TestRBACEndpoints._registered = True
        self.client = client

    # ========== NON-DESTRUCTIVE TESTS (run first) ==========

    def test_unauthenticated_gets_401(self):
        resp = self.client.get('/api/admin/users')
        assert resp.status_code in (401, 403)

    def test_admin_can_access_admin_users(self):
        resp = self.client.get('/api/admin/users', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    def test_operator_cannot_access_admin_users(self):
        resp = self.client.get('/api/admin/users', headers=_auth_header(self.operator_token))
        assert resp.status_code == 403

    def test_admin_create_org(self):
        resp = self.client.post('/api/organizations', json={'name': 'Test RBAC'},
                                headers=_auth_header(self.admin_token))
        assert resp.status_code == 201
        data = resp.get_json()
        org = data.get('org') or data.get('organization') or data
        TestRBACEndpoints.org_id = org['id']

    def test_operator_cannot_create_organization(self):
        resp = self.client.post('/api/organizations', json={'name': 'Should Fail'},
                                headers=_auth_header(self.operator_token))
        assert resp.status_code == 403

    def test_list_orgs(self):
        resp = self.client.get('/api/organizations', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        orgs = data.get('organizations', data.get('orgs', []))
        assert any(o.get('name') == 'Test RBAC' for o in orgs)

    def test_get_org(self):
        resp = self.client.get(f'/api/organizations/{self.org_id}',
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        org = data.get('org') or data.get('organization') or data
        assert org['name'] == 'Test RBAC'

    def test_update_org(self):
        resp = self.client.put(f'/api/organizations/{self.org_id}',
                               json={'name': 'Test RBAC Updated'},
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        org = data.get('org') or data.get('organization') or data
        assert org['name'] == 'Test RBAC Updated'

    def test_org_member_lifecycle(self):
        resp = self.client.post(f'/api/organizations/{self.org_id}/members',
                                json={'username': self.operator_username, 'role': 'viewer'},
                                headers=_auth_header(self.admin_token))
        assert resp.status_code in (200, 201)
        resp = self.client.get(f'/api/organizations/{self.org_id}/members',
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        members = data.get('members', [])
        assert any(m.get('username') == self.operator_username for m in members)

    def test_admin_can_access_settings_put(self):
        resp = self.client.put('/api/settings', json={'max_packets': 5000},
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    def test_operator_cannot_access_settings_put(self):
        resp = self.client.put('/api/settings', json={'max_packets': 5000},
                               headers=_auth_header(self.operator_token))
        assert resp.status_code == 403

    def test_admin_get_user(self):
        resp = self.client.get(f'/api/admin/users/{self.operator_username}',
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['user']['username'] == self.operator_username

    def test_update_user_role(self):
        resp = self.client.put(f'/api/admin/users/{self.operator_username}/role',
                               json={'role': 'viewer'},
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        assert resp.get_json()['role'] == 'viewer'

    def test_toggle_user_active(self):
        resp = self.client.put(f'/api/admin/users/{self.operator_username}/active',
                               json={'is_active': False},
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        assert resp.get_json()['is_active'] is False
        resp = self.client.put(f'/api/admin/users/{self.operator_username}/active',
                               json={'is_active': True},
                               headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        assert resp.get_json()['is_active'] is True
        # Reactivation does not restore sessions; get a fresh operator token
        login = self.client.post('/api/auth/login', json={
            'username': self.operator_username, 'password': 'StrongPass!123',
        })
        assert login.status_code == 200
        TestRBACEndpoints.operator_token = login.get_json()['token']

    def test_ml_status(self):
        resp = self.client.get('/api/ml/status', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'model_loaded' in data

    def test_ml_config(self):
        resp = self.client.get('/api/ml/config', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    # ========== DESTRUCTIVE TESTS (run last, invalidate sessions) ==========
    # Each test checks operator (expect 403) then admin (expect 200) so the
    # admin action (which may wipe sessions) is always the last operation.

    def test_clear_alerts_rbac(self):
        resp = self.client.post('/api/alerts/clear', headers=_auth_header(self.operator_token))
        assert resp.status_code == 403
        resp = self.client.post('/api/alerts/clear', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    def test_clear_logs_rbac(self):
        resp = self.client.post('/api/logs/clear', headers=_auth_header(self.operator_token))
        assert resp.status_code == 403
        resp = self.client.post('/api/logs/clear', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    def test_clear_all_rbac(self):
        resp = self.client.post('/api/clear_all', headers=_auth_header(self.operator_token))
        assert resp.status_code == 403
        resp = self.client.post('/api/clear_all', headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
        login = self.client.post('/api/auth/login', json={
            'username': self.admin_username, 'password': self.admin_password,
        })
        assert login.status_code == 200
        TestRBACEndpoints.admin_token = login.get_json()['token']

    def test_delete_org(self):
        resp = self.client.delete(f'/api/organizations/{self.org_id}',
                                  headers=_auth_header(self.admin_token))
        assert resp.status_code == 200

    def test_delete_user(self):
        resp = self.client.delete(f'/api/admin/users/{self.operator_username}',
                                  headers=_auth_header(self.admin_token))
        assert resp.status_code == 200
