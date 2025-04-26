from functools import wraps
from typing import Callable, Any
import logging
from flask import request, jsonify
from flask_login import LoginManager, UserMixin, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)

class User(UserMixin):
    def __init__(self, id: str, username: str, role: str):
        self.id = id
        self.username = username
        self.role = role

class AuthSystem:
    def __init__(self):
        self.login_manager = LoginManager()
        self.secret_key = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
        self.users = self._load_default_users()

    def _load_default_users(self) -> dict:
        """Load default users with roles"""
        return {
            'admin': {
                'id': '1',
                'username': 'admin',
                'password': generate_password_hash('admin123'),
                'role': 'admin'
            },
            'operator': {
                'id': '2',
                'username': 'operator',
                'password': generate_password_hash('operator123'),
                'role': 'operator'
            }
        }

    def init_app(self, app):
        """Initialize Flask-Login with the app"""
        self.login_manager.init_app(app)
        self.login_manager.user_loader(self.load_user)

    def load_user(self, user_id: str) -> User:
        """Load user by ID"""
        for user_data in self.users.values():
            if user_data['id'] == user_id:
                return User(
                    id=user_data['id'],
                    username=user_data['username'],
                    role=user_data['role']
                )
        return None

    def authenticate(self, username: str, password: str) -> tuple:
        """Authenticate user and return JWT token"""
        if username in self.users:
            user_data = self.users[username]
            if check_password_hash(user_data['password'], password):
                token = self._generate_token(user_data)
                return True, token
        return False, None

    def _generate_token(self, user_data: dict) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'role': user_data['role'],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token: str) -> tuple:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, 'Token expired'
        except jwt.InvalidTokenError:
            return False, 'Invalid token'

    def require_auth(self, f: Callable) -> Callable:
        """Decorator for requiring authentication"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': 'Authorization header missing'}), 401

            try:
                token = auth_header.split(' ')[1]
                is_valid, payload = self.verify_token(token)
                if not is_valid:
                    return jsonify({'error': payload}), 401

                # Add user info to request context
                request.user = User(
                    id=payload['user_id'],
                    username=payload['username'],
                    role=payload['role']
                )
                return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Authentication error: {str(e)}")
                return jsonify({'error': 'Authentication failed'}), 401

        return decorated

    def require_role(self, role: str) -> Callable:
        """Decorator for requiring specific role"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated(*args, **kwargs):
                if not hasattr(request, 'user') or request.user.role != role:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                return f(*args, **kwargs)
            return decorated
        return decorator

    def create_user(self, username: str, password: str, role: str) -> bool:
        """Create a new user"""
        if username in self.users:
            return False

        user_id = str(len(self.users) + 1)
        self.users[username] = {
            'id': user_id,
            'username': username,
            'password': generate_password_hash(password),
            'role': role
        }
        return True

    def update_user(self, username: str, password: str = None, role: str = None) -> bool:
        """Update user information"""
        if username not in self.users:
            return False

        if password:
            self.users[username]['password'] = generate_password_hash(password)
        if role:
            self.users[username]['role'] = role

        return True

    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        if username not in self.users:
            return False

        del self.users[username]
        return True 