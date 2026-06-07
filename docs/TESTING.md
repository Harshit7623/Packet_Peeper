# Testing Guide

The project uses **pytest** for unit and integration testing of the backend.

## Running the Test Suite
To run all tests with verbose output:
```bash
cd backend
pytest -v
```

To run tests with coverage reporting:
```bash
pytest --cov=backend
```

## Test Structure
There are 12 actual test functions distributed across 3 test files under `backend/tests/`:

### 1. `test_auth.py`
Tests the authentication flows, API endpoints, and token generation.
- `test_auth_service_password_validation`: Verifies password strength policies.
- `test_register_and_login_api`: Tests the full user registration, login, and token generation loop.
- `test_unauthorized_access`: Ensures protected routes reject requests without a valid token.
- `test_login_failure`: Verifies rejection of incorrect credentials.

### 2. `test_packet_sniffer.py`
Tests the packet parsing and service classification.
- `test_match_ip_service`: Tests IP-to-service matching.
- `test_classify_packet_service_dns`: Verifies DNS-based service classification.
- `test_classify_packet_service_port_fallback`: Tests fallback port-to-service mapping.
- `test_packet_sniffer_handle_packet`: Validates packet processing callbacks.
- `test_packet_sniffer_statistics`: Checks traffic and bandwidth calculations.

### 3. `test_security_monitor.py`
Tests the real-time threat detection engine.
- `test_port_scan_detection`: Validates scanning thresholds and alerts.
- `test_ddos_detection`: Tests DDoS detection limits based on packet rate.
- `test_brute_force_detection`: Ensures failed login attempts trigger brute force alerts.

## Fixtures (`conftest.py`)
The test suite utilizes shared fixtures defined in `backend/tests/conftest.py`:
- `client`: A Flask test client for making API requests.
- `app_module`: The initialized Flask app context.
- `auth_user_payload`: A dictionary containing dummy user registration/login data.
- `auth_header`: Pre-generated authorization header for testing protected endpoints.

## Adding New Tests
- Reuse existing fixtures (`client`, `auth_user_payload`, `auth_header`) found in `conftest.py`.
- Keep tests focused; avoid heavy integration scenarios unless necessary.
- Place new tests under `backend/tests/` and follow the naming pattern `test_*.py`.

---
*Documentation files are kept in the `docs/` folder and are not part of the production code.*