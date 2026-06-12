"""
Authentication & User Management Service
Secure registration, login, and session handling with JWT + bcrypt
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta
import time
from typing import Dict, Optional, Tuple, List

import bcrypt
import jwt
from flask import request, g
from functools import wraps

from config.config import ENABLE_AUTH, AUTH_TOKEN_EXPIRY

logger = logging.getLogger('packet_peeper')

VALID_ROLES = {"admin", "operator", "viewer"}

RBAC_ENDPOINT_RULES = {
    '/api/sniffing/start': {'roles': {'admin', 'operator'}},
    '/api/sniffing/stop': {'roles': {'admin', 'operator'}},
    '/api/settings': {'roles': {'admin'}, 'methods': {'PUT'}},
    '/api/clear_all': {'roles': {'admin'}},
    '/api/test-mode': {'roles': {'admin'}},
    '/api/debug/scan-tracker': {'roles': {'admin'}},
    '/api/ml/retrain': {'roles': {'admin', 'operator'}},
    '/api/ml/config': {'roles': {'admin'}, 'methods': {'POST'}},
    '/api/alerts/clear': {'roles': {'admin'}},
    '/api/logs/clear': {'roles': {'admin'}},
    '/api/network/scan': {'roles': {'admin', 'operator'}},
    '/api/admin': {'roles': {'admin'}, 'prefix': True},
    '/api/organizations': {'roles': {'admin', 'operator'}, 'prefix': True, 'write_roles': {'admin'}},
    '/api/reports/generate': {'roles': {'admin', 'operator'}},
    '/api/reports': {'roles': {'admin', 'operator', 'viewer'}, 'prefix': True, 'write_roles': {'admin'}},
}

RBAC_SOCKET_RULES = {
    'start_sniffing': {'roles': {'admin', 'operator'}},
    'stop_sniffing': {'roles': {'admin', 'operator'}},
    'clear_logs': {'roles': {'admin'}},
    'scan_devices': {'roles': {'admin', 'operator'}},
}


class AuthService:
    """Centralized auth service with JWT sessions and device fingerprinting."""

    def __init__(self, jwt_secret: str, db_service=None, token_expiry: Optional[int] = None,
                 jwt_algorithm: str = "HS256"):
        self.jwt_secret = jwt_secret
        self.db_service = db_service
        self.token_expiry = token_expiry or AUTH_TOKEN_EXPIRY
        self.jwt_algorithm = jwt_algorithm
        self.password_requirements = {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_special': True,
        }
        # Fallback in-memory sessions when DB is unavailable
        self._sessions: Dict[str, Dict] = {}

    # ============== TOKEN HELPERS ==============

    def extract_token(self, req) -> str:
        auth_header = req.headers.get('Authorization', '')
        if auth_header.lower().startswith('bearer '):
            return auth_header.split(' ', 1)[1].strip()
        return req.cookies.get('pp_auth_token', '').strip()

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    def _build_device_fingerprint(self, device_info: Dict) -> str:
        parts = [
            device_info.get('ip_address', ''),
            device_info.get('mac_address', ''),
            device_info.get('hostname', ''),
            device_info.get('user_agent', ''),
        ]
        base = '|'.join(parts)
        return hashlib.sha256(base.encode('utf-8')).hexdigest()

    # ============== VALIDATION ==============

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        req = self.password_requirements

        if len(password) < req['min_length']:
            return False, f"Password must be at least {req['min_length']} characters"
        if req['require_uppercase'] and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if req['require_lowercase'] and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if req['require_digits'] and not re.search(r'[0-9]', password):
            return False, "Password must contain at least one digit"
        if req['require_special'] and not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?]', password):
            return False, "Password must contain at least one special character"

        return True, ""

    def validate_username(self, username: str) -> Tuple[bool, str]:
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 32:
            return False, "Username must be no more than 32 characters"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscore, and dash"

        if self.db_service and self.db_service.user_exists(username=username):
            return False, "Username already exists"

        return True, ""

    def validate_email(self, email: str) -> Tuple[bool, str]:
        if not email:
            return False, "Email is required"
        if len(email) > 255:
            return False, "Email must be no more than 255 characters"
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            return False, "Invalid email format"

        if self.db_service and self.db_service.user_exists(email=email):
            return False, "Email already exists"

        return True, ""

    # ============== PASSWORD HASHING ==============

    def _hash_password(self, password: str) -> str:
        password_bytes = password.encode('utf-8')
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        return hashed.decode('utf-8')

    def _verify_password(self, password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False

    # ============== REGISTRATION ==============

    def register_user(self, username: str, email: str, password: str,
                      device_info: Optional[Dict] = None,
                      default_org_id: Optional[int] = None) -> Tuple[bool, str, Optional[Dict]]:
        normalized_email = email.strip().lower()

        valid, msg = self.validate_username(username)
        if not valid:
            logger.warning(f"Registration failed for {username}: {msg}")
            return False, msg, None

        valid, msg = self.validate_email(normalized_email)
        if not valid:
            logger.warning(f"Registration failed for {username}: {msg}")
            return False, msg, None

        valid, msg = self.validate_password_strength(password)
        if not valid:
            logger.warning(f"Registration failed for {username}: {msg}")
            return False, msg, None

        if not self.db_service:
            return False, "Database service not available", None

        role = "operator"
        try:
            if self.db_service.get_user_count() == 0:
                role = "admin"
        except Exception:
            role = "operator"

        if role not in VALID_ROLES:
            role = "operator"

        password_hash = self._hash_password(password)
        user_data = {
            'username': username,
            'email': normalized_email,
            'password_hash': password_hash,
            'created_at': datetime.utcnow().isoformat(),
            'is_admin': role == "admin",
            'role': role,
            'default_org_id': default_org_id,
            'device_info': device_info or {},
            'last_login': None,
            'login_attempts': 0,
            'locked_until': None,
        }

        success = self.db_service.create_user(user_data)
        if not success:
            return False, "Failed to save user to database", None

        logger.info(f"User registered: {username} ({role})")
        user_data.pop('password_hash', None)
        return True, "User registered successfully", user_data

    # ============== LOGIN ==============

    def login_user(self, identifier: str, password: str,
                   device_info: Optional[Dict] = None) -> Tuple[bool, str, Optional[str], Optional[Dict]]:
        if not self.db_service:
            return False, "Database service not available", None, None

        normalized_identifier = identifier.strip()
        if '@' in normalized_identifier:
            normalized_identifier = normalized_identifier.lower()

        user = self.db_service.get_user_by_identifier(normalized_identifier)
        if not user:
            logger.warning(f"Login attempt for non-existent user: {identifier}")
            return False, "Invalid username or password", None, None

        if not user.get('is_active', True):
            return False, "Account disabled", None, None

        locked_until_value = user.get('locked_until')
        if locked_until_value:
            locked_until = datetime.fromisoformat(locked_until_value)
            if datetime.utcnow() < locked_until:
                remaining = max(1, int((locked_until - datetime.utcnow()).total_seconds() // 60))
                logger.warning(f"Login attempt on locked account {user.get('username')} ({remaining} min)")
                return False, f"Account temporarily locked. Try again in {remaining} minutes.", None, None

        password_hash = user.get('password_hash') or ''
        if not self._verify_password(password, password_hash):
            attempts = int(user.get('login_attempts', 0)) + 1
            update = {'login_attempts': attempts}

            if attempts >= 5:
                locked_until = datetime.utcnow() + timedelta(minutes=15)
                update['locked_until'] = locked_until.isoformat()
                logger.warning(f"Account locked due to failed login attempts: {user.get('username')}")

            self.db_service.update_user(user.get('username'), update)
            logger.warning(f"Failed login attempt for {user.get('username')} (attempt {attempts})")
            return False, "Invalid username or password", None, None

        session_id = secrets.token_urlsafe(16)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.token_expiry)
        device_payload = device_info or {}
        device_fingerprint = self._build_device_fingerprint(device_payload)

        token_payload = {
            'sub': user.get('username'),
            'uid': user.get('id'),
            'role': user.get('role', 'operator'),
            'oid': user.get('default_org_id'),
            'sid': session_id,
            'dfp': device_fingerprint,
            'iat': int(time.time()),
            'exp': int(time.time()) + self.token_expiry,
        }

        token = jwt.encode(token_payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        self.db_service.update_user(user.get('username'), {
            'login_attempts': 0,
            'locked_until': None,
            'last_login': now.isoformat(),
            'device_info': device_payload,
        })

        token_hash = self._hash_token(token)
        session_data = {
            'user_id': user.get('id'),
            'token_hash': token_hash,
            'device_fingerprint': device_fingerprint,
            'device_info': device_payload,
            'created_at': now,
            'last_seen': now,
            'expires_at': expires_at,
        }

        stored = self.db_service.create_user_session(session_data)
        if not stored:
            self._sessions[token_hash] = session_data

        logger.info(f"User logged in: {user.get('username')}")

        user_data = {
            'username': user.get('username'),
            'email': user.get('email'),
            'created_at': user.get('created_at'),
            'last_login': now.isoformat(),
            'role': user.get('role', 'operator'),
            'default_org_id': user.get('default_org_id'),
            'device_info': device_payload,
        }

        return True, "Login successful", token, user_data

    # ============== TOKEN VALIDATION ==============

    def verify_token(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        if not token:
            return None, "missing_token"

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
                options={'require': ['exp', 'iat', 'sub', 'sid']},
            )
        except jwt.ExpiredSignatureError:
            return None, "token_expired"
        except jwt.InvalidTokenError:
            return None, "invalid_token"

        token_hash = self._hash_token(token)

        session = None
        if self.db_service:
            session = self.db_service.get_session_by_token_hash(token_hash)
        else:
            session = self._sessions.get(token_hash)

        if not session:
            return None, "session_not_found"

        expires_at_value = session.get('expires_at')
        if isinstance(expires_at_value, str):
            expires_at = datetime.fromisoformat(expires_at_value)
        else:
            expires_at = expires_at_value

        if expires_at and datetime.utcnow() >= expires_at:
            self.logout_user(token)
            return None, "token_expired"

        if payload.get('dfp') and session.get('device_fingerprint'):
            if payload.get('dfp') != session.get('device_fingerprint'):
                return None, "device_mismatch"

        if self.db_service:
            user = self.db_service.get_user(payload.get('sub'))
            if not user or not user.get('is_active', True):
                return None, "user_inactive"
            payload['role'] = user.get('role', payload.get('role'))
            payload['oid'] = user.get('default_org_id', payload.get('oid'))

            self.db_service.touch_session(token_hash)
        else:
            session['last_seen'] = datetime.utcnow()

        return payload, None

    # ============== PROFILE & SESSIONS ==============

    def get_user_profile(self, username: str) -> Optional[Dict]:
        if not self.db_service:
            return None

        user = self.db_service.get_user(username)
        if not user:
            return None

        sessions = self.db_service.get_user_sessions(user.get('id'), include_expired=False)
        organizations = self.db_service.get_user_organizations(user.get('id'))

        return {
            'username': user.get('username'),
            'email': user.get('email'),
            'role': user.get('role', 'operator'),
            'default_org_id': user.get('default_org_id'),
            'created_at': user.get('created_at'),
            'last_login': user.get('last_login'),
            'device_info': user.get('device_info', {}),
            'active_sessions': sessions,
            'active_session_count': len(sessions),
            'organizations': organizations,
        }

    def update_profile(self, username: str, updates: Dict) -> Tuple[bool, str]:
        if not self.db_service:
            return False, "Database service not available"

        safe_fields = ['device_info', 'preferences', 'email']
        safe_updates = {k: v for k, v in updates.items() if k in safe_fields}

        if 'email' in safe_updates and isinstance(safe_updates['email'], str):
            safe_updates['email'] = safe_updates['email'].strip().lower()

        if 'email' in safe_updates:
            current = self.db_service.get_user(username)
            if current and current.get('email') != safe_updates['email']:
                valid, msg = self.validate_email(safe_updates['email'])
                if not valid:
                    return False, msg
            elif current and current.get('email') == safe_updates['email']:
                safe_updates.pop('email', None)

        if not safe_updates:
            return False, "No valid fields to update"

        success = self.db_service.update_user(username, safe_updates)
        if success:
            logger.info(f"Profile updated for {username}")
            return True, "Profile updated successfully"

        return False, "Failed to update profile"

    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        if not self.db_service:
            return False, "Database service not available"

        user = self.db_service.get_user(username)
        if not user:
            return False, "User not found"

        if not self._verify_password(old_password, user.get('password_hash', '')):
            logger.warning(f"Failed password change attempt for {username}")
            return False, "Current password is incorrect"

        valid, msg = self.validate_password_strength(new_password)
        if not valid:
            return False, msg

        new_hash = self._hash_password(new_password)
        success = self.db_service.update_user(username, {'password_hash': new_hash})
        if success:
            logger.info(f"Password changed for {username}")
            return True, "Password changed successfully"

        return False, "Failed to change password"

    def logout_user(self, token: str) -> bool:
        token_hash = self._hash_token(token)
        deleted = False

        if self.db_service:
            deleted = self.db_service.delete_session(token_hash)
        else:
            deleted = token_hash in self._sessions
            self._sessions.pop(token_hash, None)

        if deleted:
            logger.info("User logged out")
        return deleted

    def cleanup_expired_sessions(self) -> int:
        if self.db_service:
            return self.db_service.cleanup_expired_sessions()

        now = datetime.utcnow()
        expired = [
            token_hash
            for token_hash, session in self._sessions.items()
            if session.get('expires_at') and session.get('expires_at') <= now
        ]
        for token_hash in expired:
            self._sessions.pop(token_hash, None)
        return len(expired)


def require_auth(roles: Optional[List[str]] = None):
    """Decorator to require authentication on Flask routes.

    Can be used as either `@require_auth` or `@require_auth(['admin'])`.
    """

    def _decorator(func):
        role_set = set(roles or [])

        @wraps(func)
        def wrapped(*args, **kwargs):
            if not ENABLE_AUTH:
                return func(*args, **kwargs)

            auth_service = g.get('auth_service')
            if not auth_service:
                return {'error': 'Authentication service unavailable'}, 500

            token = auth_service.extract_token(request)
            payload, error_code = auth_service.verify_token(token)
            if error_code:
                return {'error': 'Authentication required', 'code': error_code}, 401

            g.current_user = payload.get('sub')
            g.current_user_id = payload.get('uid')
            g.current_role = payload.get('role')
            g.current_session_id = payload.get('sid')

            if role_set and payload.get('role') not in role_set:
                return {'error': 'Insufficient permissions'}, 403

            return func(*args, **kwargs)

        return wrapped

    # Support usage as @require_auth without parentheses
    if callable(roles):
        func = roles  # type: ignore
        roles = None
        return _decorator(func)

    return _decorator
