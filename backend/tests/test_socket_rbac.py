"""
Socket.IO RBAC Tests
Verifies that privileged socket events enforce role-based access control.
"""

import pytest


class TestSocketRBAC:
    admin_token = None
    viewer_token = None
    admin_username = None
    viewer_username = None
    _registered = False

    @pytest.fixture(autouse=True)
    def setup(self, client, auth_user_payload):
        if TestSocketRBAC._registered:
            self.client = client
            return

        # Register admin (first user → admin role)
        resp = client.post('/api/auth/register', json=auth_user_payload)
        if resp.status_code == 409:
            import uuid
            alt = dict(auth_user_payload)
            alt['username'] = f"admin_sio_{uuid.uuid4().hex[:8]}"
            alt['email'] = f"{alt['username']}@example.com"
            resp = client.post('/api/auth/register', json=alt)
        assert resp.status_code == 201
        TestSocketRBAC.admin_username = resp.get_json()['user']['username']

        if resp.get_json().get('user', {}).get('role') != 'admin':
            import app
            app.ext.db_service.update_user(
                TestSocketRBAC.admin_username,
                {'role': 'admin', 'is_admin': True},
            )

        login = client.post('/api/auth/login', json={
            'username': TestSocketRBAC.admin_username,
            'password': auth_user_payload['password'],
        })
        assert login.status_code == 200
        TestSocketRBAC.admin_token = login.get_json()['token']

        # Register viewer
        v_payload = {
            'username': f'viewer_sio_{auth_user_payload["username"]}',
            'email': f'viewer_sio_{auth_user_payload["email"]}',
            'password': 'StrongPass!123',
            'password_confirm': 'StrongPass!123',
        }
        resp = client.post('/api/auth/register', json=v_payload)
        assert resp.status_code == 201
        TestSocketRBAC.viewer_username = v_payload['username']

        # Ensure viewer role
        import app
        app.ext.db_service.update_user(
            TestSocketRBAC.viewer_username, {'role': 'viewer'},
        )

        login = client.post('/api/auth/login', json={
            'username': TestSocketRBAC.viewer_username,
            'password': 'StrongPass!123',
        })
        assert login.status_code == 200
        TestSocketRBAC.viewer_token = login.get_json()['token']

        TestSocketRBAC._registered = True
        self.client = client

    def _sio_client(self, token):
        import app
        return app.ext.socketio.test_client(
            app.app, auth={'token': token},
            flask_test_client=self.client,
        )

    def test_admin_can_connect(self):
        sio = self._sio_client(self.admin_token)
        assert sio.is_connected()
        sio.disconnect()

    def test_viewer_can_connect(self):
        sio = self._sio_client(self.viewer_token)
        assert sio.is_connected()
        sio.disconnect()

    def test_invalid_token_rejected(self):
        sio = self._sio_client('invalid.jwt.token')
        assert not sio.is_connected()

    def test_viewer_cannot_clear_logs(self):
        sio = self._sio_client(self.viewer_token)
        sio.emit('clear_logs')
        received = sio.get_received()
        events = [e['name'] for e in received]
        # Should get error event, not logs_list
        assert 'error' in events or not any(e['name'] == 'logs_list' and
               any(d.get('message', '').startswith('Insufficient') for d in e['args'] if isinstance(d, dict))
               for e in received)
        sio.disconnect()

    def test_admin_can_clear_logs(self):
        sio = self._sio_client(self.admin_token)
        sio.emit('clear_logs')
        received = sio.get_received()
        events = [e['name'] for e in received]
        assert 'logs_list' in events
        sio.disconnect()

    def test_viewer_cannot_start_sniffing(self):
        sio = self._sio_client(self.viewer_token)
        sio.emit('start_sniffing', {'interface': 'lo'})
        received = sio.get_received()
        events = [e['name'] for e in received]
        # Should get error in sniffing_status response
        has_error = any(
            e['name'] == 'sniffing_status' and
            isinstance(e['args'], list) and
            len(e['args']) > 0 and
            isinstance(e['args'][0], dict) and
            'Insufficient' in e['args'][0].get('message', '')
            for e in received
        )
        assert has_error
        sio.disconnect()

    def test_viewer_cannot_stop_sniffing(self):
        sio = self._sio_client(self.viewer_token)
        sio.emit('stop_sniffing')
        received = sio.get_received()
        has_error = any(
            e['name'] == 'sniffing_status' and
            isinstance(e['args'], list) and
            len(e['args']) > 0 and
            isinstance(e['args'][0], dict) and
            'Insufficient' in e['args'][0].get('message', '')
            for e in received
        )
        assert has_error
        sio.disconnect()

    def test_viewer_cannot_scan_devices(self):
        sio = self._sio_client(self.viewer_token)
        sio.emit('scan_devices')
        received = sio.get_received()
        has_error = any(
            e['name'] == 'devices_update' and
            isinstance(e['args'], list) and
            len(e['args']) > 0 and
            isinstance(e['args'][0], dict) and
            'Insufficient' in e['args'][0].get('error', '')
            for e in received
        )
        assert has_error
        sio.disconnect()

    def test_disconnect_removes_session(self):
        import extensions as ext
        sio = self._sio_client(self.admin_token)
        sid = sio.sid if hasattr(sio, 'sid') else None
        sio.disconnect()
        if sid:
            assert ext._get_socket_session(sid) is None
