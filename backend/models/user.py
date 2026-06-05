"""User model for database persistence"""
from datetime import datetime
import bcrypt

class User:
    """User entity with secure password handling"""
    
    def __init__(self, id=None, username=None, email=None, password_hash=None,
                 is_admin=False, role="operator", created_at=None, last_login=None,
                 is_active=True, device_info=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.role = role
        self.is_active = is_active
        self.device_info = device_info or {}
        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login
    
    @staticmethod
    def hash_password(password):
        """Hash a plaintext password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password):
        """Verify a plaintext password against stored bcrypt hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self):
        """Convert user to dictionary for API responses (excludes password)"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'role': self.role,
            'is_active': self.is_active,
            'device_info': self.device_info,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class UserSession:
    """User session for JWT token management"""
    
    def __init__(self, id=None, user_id=None, token_hash=None, device_info=None, 
                 expires_at=None, created_at=None):
        self.id = id
        self.user_id = user_id
        self.token_hash = token_hash
        self.device_info = device_info or {}
        self.expires_at = expires_at
        self.created_at = created_at or datetime.utcnow()
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_info': self.device_info,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
