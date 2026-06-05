"""
User Management & Authentication Service
Handles user registration, authentication, profile management with bcrypt password hashing
"""

import re
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from functools import wraps

import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import request, g

logger = logging.getLogger('packet_peeper')

class UserService:
    """Centralized user management with secure password handling"""
    
    def __init__(self, jwt_secret: str, db_service=None):
        """
        Initialize user service
        
        Args:
            jwt_secret: Secret key for token generation
            db_service: Database service instance for persistence
        """
        self.jwt_secret = jwt_secret
        self.db_service = db_service
        self.token_serializer = URLSafeTimedSerializer(jwt_secret, salt='packet-peeper-user-token')
        self.password_requirements = {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_special': True
        }
        # In-memory session store (replace with DB for production)
        self._sessions: Dict[str, Dict] = {}
    
    # ============== PASSWORD VALIDATION ==============
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password meets enterprise security requirements
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple (is_valid, error_message)
        """
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
        """Validate username format and availability"""
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 32:
            return False, "Username must be no more than 32 characters"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscore, and dash"
        if self.db_service and self.db_service.user_exists(username):
            return False, "Username already exists"
        return True, ""
    
    # ============== USER REGISTRATION ==============
    
    def register_user(self, username: str, password: str, device_info: Dict = None) -> Tuple[bool, str, Optional[Dict]]:
        """
        Register a new user
        
        Args:
            username: Desired username
            password: Desired password
            device_info: Optional device info {mac_address, ip_address, hostname}
            
        Returns:
            Tuple (success, message, user_data)
        """
        # Validate username
        valid, msg = self.validate_username(username)
        if not valid:
            logger.warning(f"Registration failed for {username}: {msg}")
            return False, msg, None
        
        # Validate password
        valid, msg = self.validate_password_strength(password)
        if not valid:
            logger.warning(f"Registration failed for {username}: {msg}")
            return False, msg, None
        
        # Generate password hash
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        try:
            # Save user to database
            if self.db_service:
                user_data = {
                    'username': username,
                    'password_hash': password_hash,
                    'created_at': datetime.utcnow().isoformat(),
                    'is_admin': False,
                    'device_info': device_info or {},
                    'last_login': None,
                    'login_attempts': 0,
                    'locked_until': None
                }
                success = self.db_service.create_user(user_data)
                if success:
                    logger.info(f"User registered: {username}")
                    # Don't return password hash
                    user_data.pop('password_hash')
                    return True, "User registered successfully", user_data
                else:
                    return False, "Failed to save user to database", None
            else:
                return False, "Database service not available", None
        
        except Exception as e:
            logger.error(f"Registration error for {username}: {str(e)}")
            return False, "Registration failed. Please try again.", None
    
    # ============== USER LOGIN ==============
    
    def login_user(self, username: str, password: str, device_info: Dict = None) -> Tuple[bool, str, Optional[str], Optional[Dict]]:
        """
        Authenticate user and generate session token
        
        Args:
            username: Username
            password: Password
            device_info: Current device info
            
        Returns:
            Tuple (success, message, token, user_data)
        """
        try:
            if not self.db_service:
                return False, "Database service not available", None, None
            
            # Check if account is locked
            user = self.db_service.get_user(username)
            if not user:
                logger.warning(f"Login attempt for non-existent user: {username}")
                return False, "Invalid username or password", None, None
            
            # Check if account is temporarily locked (brute force protection)
            if user.get('locked_until'):
                locked_until = datetime.fromisoformat(user['locked_until'])
                if datetime.utcnow() < locked_until:
                    remaining = (locked_until - datetime.utcnow()).seconds // 60
                    logger.warning(f"Login attempt on locked account {username}, {remaining} min remaining")
                    return False, f"Account temporarily locked. Try again in {remaining} minutes.", None, None
                else:
                    # Unlock account
                    self.db_service.update_user(username, {'locked_until': None, 'login_attempts': 0})
            
            # Verify password
            password_hash = user.get('password_hash')
            if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                # Increment failed attempts
                attempts = user.get('login_attempts', 0) + 1
                update = {'login_attempts': attempts}
                
                # Lock account after 5 failed attempts
                if attempts >= 5:
                    locked_until = datetime.utcnow() + timedelta(minutes=15)
                    update['locked_until'] = locked_until.isoformat()
                    logger.warning(f"Account locked due to failed login attempts: {username}")
                
                self.db_service.update_user(username, update)
                logger.warning(f"Failed login attempt for {username} (attempt {attempts})")
                return False, "Invalid username or password", None, None
            
            # Reset login attempts on successful login
            self.db_service.update_user(username, {
                'login_attempts': 0,
                'locked_until': None,
                'last_login': datetime.utcnow().isoformat(),
                'device_info': device_info or {}
            })
            
            # Generate token
            token_data = {
                'username': username,
                'user_id': user.get('id'),
                'timestamp': datetime.utcnow().isoformat(),
                'device_info': device_info or {}
            }
            token = self.token_serializer.dumps(token_data)
            
            # Store session
            self._sessions[token] = {
                'username': username,
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=8),  # 8-hour session
                'device_info': device_info
            }
            
            logger.info(f"User logged in: {username}")
            
            # Return user data without password
            user_data = {
                'username': user.get('username'),
                'created_at': user.get('created_at'),
                'is_admin': user.get('is_admin', False),
                'device_info': user.get('device_info', {})
            }
            
            return True, "Login successful", token, user_data
        
        except Exception as e:
            logger.error(f"Login error for {username}: {str(e)}")
            return False, "Login failed. Please try again.", None, None
    
    # ============== TOKEN VALIDATION ==============
    
    def validate_token(self, token: str, max_age: int = 28800) -> Tuple[bool, Optional[Dict]]:
        """
        Validate authentication token
        
        Args:
            token: JWT token to validate
            max_age: Maximum age of token in seconds (default 8 hours)
            
        Returns:
            Tuple (is_valid, token_data)
        """
        try:
            token_data = self.token_serializer.loads(token, max_age=max_age)
            
            # Check session store
            if token in self._sessions:
                session = self._sessions[token]
                if datetime.utcnow() < session['expires_at']:
                    return True, token_data
                else:
                    del self._sessions[token]
                    logger.info(f"Session expired for {token_data.get('username')}")
                    return False, None
            
            return False, None
        
        except SignatureExpired:
            logger.debug("Token expired")
            return False, None
        except BadSignature:
            logger.warning("Invalid token signature")
            return False, None
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return False, None
    
    # ============== USER PROFILE ==============
    
    def get_user_profile(self, username: str) -> Optional[Dict]:
        """Get user profile information"""
        if not self.db_service:
            return None
        
        user = self.db_service.get_user(username)
        if not user:
            return None
        
        return {
            'username': user.get('username'),
            'created_at': user.get('created_at'),
            'is_admin': user.get('is_admin', False),
            'last_login': user.get('last_login'),
            'device_info': user.get('device_info', {}),
            'login_count': user.get('login_count', 0)
        }
    
    def update_profile(self, username: str, updates: Dict) -> Tuple[bool, str]:
        """Update user profile (safe fields only)"""
        if not self.db_service:
            return False, "Database service not available"
        
        # Only allow safe fields to be updated
        safe_fields = ['device_info', 'preferences']
        safe_updates = {k: v for k, v in updates.items() if k in safe_fields}
        
        if not safe_updates:
            return False, "No valid fields to update"
        
        success = self.db_service.update_user(username, safe_updates)
        if success:
            logger.info(f"Profile updated for {username}")
            return True, "Profile updated successfully"
        else:
            return False, "Failed to update profile"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password"""
        if not self.db_service:
            return False, "Database service not available"
        
        user = self.db_service.get_user(username)
        if not user:
            return False, "User not found"
        
        # Verify old password
        if not check_password_hash(user.get('password_hash'), old_password):
            logger.warning(f"Failed password change attempt for {username}")
            return False, "Current password is incorrect"
        
        # Validate new password
        valid, msg = self.validate_password_strength(new_password)
        if not valid:
            return False, msg
        
        # Update password
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        success = self.db_service.update_user(username, {'password_hash': new_hash})
        
        if success:
            logger.info(f"Password changed for {username}")
            return True, "Password changed successfully"
        else:
            return False, "Failed to change password"
    
    # ============== SESSION MANAGEMENT ==============
    
    def logout_user(self, token: str) -> bool:
        """Logout user and invalidate token"""
        if token in self._sessions:
            del self._sessions[token]
            logger.info("User logged out")
            return True
        return False
    
    def get_active_sessions(self, username: str) -> int:
        """Get count of active sessions for user"""
        count = 0
        for token, session in self._sessions.items():
            if session.get('username') == username and datetime.utcnow() < session['expires_at']:
                count += 1
        return count
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions (call periodically)"""
        expired = [token for token, session in self._sessions.items()
                  if datetime.utcnow() >= session['expires_at']]
        for token in expired:
            del self._sessions[token]
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired sessions")


def require_auth(f):
    """Decorator to require authentication on Flask route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return {'error': 'Missing authentication token'}, 401
        
        # This should be called with user_service instance in Flask g object
        user_service = g.get('user_service')
        if not user_service:
            return {'error': 'Authentication service unavailable'}, 500
        
        is_valid, token_data = user_service.validate_token(token)
        if not is_valid:
            return {'error': 'Invalid or expired token'}, 401
        
        # Store in g for use in route
        g.current_user = token_data.get('username')
        g.token_data = token_data
        
        return f(*args, **kwargs)
    
    return decorated_function
