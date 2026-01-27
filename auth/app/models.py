import secrets

import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import deferred

db = SQLAlchemy()


class UserSession(db.Model):
    """Модель для хранения сессий пользователей."""

    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False, index=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    refresh_token_hash = db.Column(db.String(128), nullable=False)  # Храним как hex строку
    user_agent_hash = db.Column(db.String(128), nullable=False)  # Храним как hex строку
    created_at = db.Column(db.DateTime, default=datetime.now(), nullable=False, index=True)
    last_used = db.Column(db.DateTime, default=datetime.now(), nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    user_agent_original = db.Column(db.Text, nullable=True)

    account = db.relationship('Account', backref=db.backref('sessions', lazy='dynamic'))

    def __init__(self, **kwargs):
        if 'created_at' not in kwargs:
            kwargs['created_at'] = datetime.now()
        if 'last_used' not in kwargs:
            kwargs['last_used'] = datetime.now()
        super().__init__(**kwargs)


class Account(db.Model):
    """Модель аккаунта."""

    __tablename__ = 'accounts'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = deferred(db.Column(db.String(128), nullable=False))
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, index=True)
    public_id = db.Column(db.String(16), unique=True, nullable=False, index=True)

    # Поля для двухфакторной аутентификации
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

    # Поля для блокировки аккаунта
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True, index=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)

    # Оставленные поля уведомлений
    email_notifications = db.Column(db.Boolean, default=True, nullable=False)
    max_sessions = db.Column(db.Integer, default=5, nullable=False)

    def __init__(self, **kwargs):
        """Инициализация с оптимизацией."""
        super().__init__(**kwargs)
        if not self.public_id:
            self.public_id = self._fast_public_id()

    @staticmethod
    def _fast_public_id() -> str:
        """Быстрая генерация публичного ID."""
        return secrets.token_urlsafe(12)[:16]

    def set_password(self, password: str) -> None:
        """Быстрая установка пароля."""
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')