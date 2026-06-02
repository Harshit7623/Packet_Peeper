import importlib
import uuid
import pytest


def _set_test_env(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("packet_peeper_data")
    mp = pytest.MonkeyPatch()
    mp.setenv("PACKET_PEEPER_DESKTOP", "True")
    mp.setenv("PACKET_PEEPER_DATA_DIR", str(data_dir))
    mp.setenv("AUTO_START_SNIFFING", "False")
    mp.setenv("ENABLE_AUTH", "True")
    mp.setenv("JWT_SECRET", "test-secret")
    mp.setenv("DB_ENGINE", "sqlite")
    mp.setenv("ASYNC_PROCESSING", "False")
    mp.setenv("CAPTURE_MODE", "lite")
    mp.setenv("ENABLE_VENDOR_LOOKUP", "False")
    mp.setenv("FLASK_ENV", "testing")
    mp.setenv("FLASK_DEBUG", "False")
    mp.setenv("SOCKETIO_ASYNC_MODE", "threading")
    return mp


@pytest.fixture(scope="session")
def app_module(tmp_path_factory):
    mp = _set_test_env(tmp_path_factory)
    import config.config as config
    importlib.reload(config)
    import app as app_module
    importlib.reload(app_module)
    yield app_module
    mp.undo()


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()


@pytest.fixture()
def auth_user_payload():
    suffix = uuid.uuid4().hex[:8]
    return {
        "username": f"tester_{suffix}",
        "email": f"tester_{suffix}@example.com",
        "password": "StrongPass!123",
        "password_confirm": "StrongPass!123",
    }


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def auth_header():
    return _auth_header
