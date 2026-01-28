import secrets
import string
import bcrypt
import json
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
import redis
import logging
import re
import requests
from flask import current_app
from .models import Account, ServiceToken, db
import jwt
import hashlib

logger = logging.getLogger(__name__)

# Redis клиент
redis_client = None


def generate_service_token(length: int = 64) -> str:
    """
    Генерация токена для сервиса.

    Args:
        length: Длина токена

    Returns:
        Строка с токеном
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_service_token(token: str) -> str:
    """
    Хеширование токена сервиса.

    Args:
        token: Токен для хеширования

    Returns:
        Hex-строка хеша
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_service_token(service_name: str, description: str = None,
                         valid_days: int = 180) -> Optional[Dict[str, Any]]:
    """
    Создание токена для сервиса.

    Args:
        service_name: Название сервиса
        description: Описание токена (опционально)
        valid_days: Срок действия в днях

    Returns:
        Словарь с токеном и информацией или None при ошибке
    """
    try:
        # Генерируем токен
        token = generate_service_token()
        token_hash = hash_service_token(token)

        # Рассчитываем срок действия
        created_at = datetime.now()
        expires_at = created_at + timedelta(days=valid_days)

        # Создаем запись в БД
        service_token = ServiceToken(
            service_name=service_name,
            token_hash=token_hash,
            description=description,
            created_at=created_at,
            expires_at=expires_at,
            is_active=True
        )

        db.session.add(service_token)
        db.session.commit()

        logger.info(f"Service token created for service: {service_name}")

        return {
            'token': token,
            'service_name': service_name,
            'created_at': created_at.isoformat(),
            'expires_at': expires_at.isoformat(),
            'valid_days': valid_days
        }

    except Exception as e:
        logger.error(f"Failed to create service token: {e}", exc_info=True)
        db.session.rollback()
        return None


def validate_service_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Проверка валидности токена сервиса.

    Args:
        token: Токен для проверки

    Returns:
        Информация о токене или None если невалиден
    """
    try:
        # Хешируем токен для поиска
        token_hash = hash_service_token(token)

        # Ищем токен в БД
        service_token = ServiceToken.query.filter_by(
            token_hash=token_hash,
            is_active=True
        ).first()

        if not service_token:
            logger.warning(f"Service token not found or inactive")
            return None

        # Проверяем срок действия
        if datetime.now() > service_token.expires_at:
            # Помечаем как неактивный
            service_token.is_active = False
            db.session.commit()
            logger.info(f"Service token expired for service: {service_token.service_name}")
            return None

        # Обновляем время последнего использования
        service_token.last_used = datetime.now()
        db.session.commit()

        logger.debug(f"Service token validated for: {service_token.service_name}")

        return {
            'id': service_token.id,
            'service_name': service_token.service_name,
            'description': service_token.description,
            'created_at': service_token.created_at,
            'expires_at': service_token.expires_at,
            'last_used': service_token.last_used
        }

    except Exception as e:
        logger.error(f"Error validating service token: {e}")
        return None


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Проверка надежности пароля.

    Args:
        password: Пароль для проверки

    Returns:
        Кортеж (is_valid, error_message)
    """
    # Минимальная длина
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов"

    # Проверка на наличие цифр
    if not re.search(r'\d', password):
        return False, "Пароль должен содержать хотя бы одну цифру"

    # Проверка на наличие заглавной буквы
    if not re.search(r'[A-ZА-Я]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"

    # Проверка на наличие строчной буквы
    if not re.search(r'[a-zа-я]', password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"

    # Дополнительно: проверка на специальные символы (опционально, но рекомендуется)
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
        current_app.logger.warning("Пароль не содержит специальных символов")
        # Не блокируем, только предупреждаем в логах

    return True, "Пароль соответствует требованиям безопасности"


def get_redis_client():
    """Инициализация и получение Redis клиента через URL."""
    global redis_client
    if redis_client is None:
        try:
            # Получаем URL из конфига
            redis_url = current_app.config.get('REDIS_CODES_URL')

            # Подключаемся к редису
            redis_client = redis.Redis.from_url(
                redis_url,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=10
            )

            # Проверяем соединение
            redis_client.ping()
            logger.info(f"Redis connection established: {redis_url.split('@')[-1]}")

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    return redis_client


def generate_verification_code(length: int = 6) -> str:
    """
    Генерация случайного цифрового кода.

    Args:
        length: Длина кода (по умолчанию 6)

    Returns:
        Строка с цифровым кодом
    """
    digits = string.digits
    return ''.join(secrets.choice(digits) for _ in range(length))


def hash_verification_code(code: str) -> Tuple[bytes, bytes]:
    """
    Хеширование кода подтверждения с солью.

    Args:
        code: Код для хеширования

    Returns:
        Кортеж (хеш, соль)
    """
    salt = bcrypt.gensalt()
    # Преобразуем код в bytes для хеширования
    code_bytes = code.encode('utf-8')
    hashed = bcrypt.hashpw(code_bytes, salt)
    return hashed, salt


def verify_code_hash(code: str, hashed_code: bytes, salt: bytes) -> bool:
    """
    Проверка кода подтверждения.

    Args:
        code: Введенный код
        hashed_code: Хранимый хеш
        salt: Соль

    Returns:
        True если код верный, иначе False
    """
    try:
        code_bytes = code.encode('utf-8')
        new_hash = bcrypt.hashpw(code_bytes, salt)
        return new_hash == hashed_code
    except Exception as e:
        logger.error(f"Error verifying code hash: {e}")
        return False


def create_verification_code(user_id: int, operation: str, ttl_minutes: int = 10) -> Optional[str]:
    """
    Создание и сохранение кода подтверждения в Redis.

    Args:
        user_id: ID пользователя
        operation: Тип операции (например, 'register', 'reset_password')
        ttl_minutes: Время жизни кода в минутах

    Returns:
        Сгенерированный код или None при ошибке
    """
    global redis_client
    try:
        redis_client = get_redis_client()

        # Удаляем старый код, если существует (максимум 1 код на пользователя)
        delete_verification_code(user_id, operation)

        # Генерируем новый код
        code = generate_verification_code()

        # Хешируем код
        hashed_code, salt = hash_verification_code(code)

        # Создаем ключ для Redis
        redis_key = f"verification_code:{user_id}:{operation}"

        # Подготавливаем данные для хранения
        code_data = {
            'hashed_code': hashed_code.hex(),  # Храним как hex строку
            'salt': salt.hex(),  # Храним как hex строку
            'created_at': datetime.now().isoformat(),
            'failed_attempts': 0,
            'used': False
        }

        # Сохраняем в Redis с TTL
        ttl_seconds = ttl_minutes * 60
        redis_client.setex(
            redis_key,
            ttl_seconds,
            json.dumps(code_data)
        )

        logger.info(f"Verification code created for user {user_id}, operation: {operation}")
        return code

    except Exception as e:
        logger.error(f"Failed to create verification code: {e}")
        return None


def verify_verification_code(user_id: int, code: str, operation: str, increment_failed: bool = True) -> bool:
    """
    Проверка кода подтверждения.

    Args:
        user_id: ID пользователя
        code: Введенный код
        operation: Тип операции
        increment_failed: Увеличивать счетчик неудачных попыток

    Returns:
        True если код верный, иначе False
    """
    global redis_client
    try:
        redis_client = get_redis_client()
        redis_key = f"verification_code:{user_id}:{operation}"

        # Получаем данные из Redis
        code_data_json = redis_client.get(redis_key)
        if not code_data_json:
            logger.warning(f"No verification code found for user {user_id}, operation: {operation}")
            return False

        # Парсим данные
        code_data = json.loads(code_data_json)

        # Проверяем, не использован ли уже код
        if code_data.get('used'):
            logger.warning(f"Verification code already used for user {user_id}")
            return False

        # Восстанавливаем байты из hex строк
        hashed_code_bytes = bytes.fromhex(code_data['hashed_code'])
        salt_bytes = bytes.fromhex(code_data['salt'])

        # Проверяем код
        is_valid = verify_code_hash(code, hashed_code_bytes, salt_bytes)

        if is_valid:
            # Если код верный - помечаем как использованный и удаляем
            code_data['used'] = True
            redis_client.setex(redis_key, 60, json.dumps(code_data))  # Сохраняем на короткое время для аудита
            logger.info(f"Verification code verified successfully for user {user_id}")
            return True
        else:
            # Если код неверный - увеличиваем счетчик неудачных попыток
            if increment_failed:
                code_data['failed_attempts'] = code_data.get('failed_attempts', 0) + 1

                # Блокировка при слишком большом количестве неудачных попыток
                if code_data['failed_attempts'] >= 5:
                    redis_client.delete(redis_key)
                    logger.warning(f"Too many failed attempts for user {user_id}, code deleted")
                else:
                    redis_client.setex(redis_key, 600, json.dumps(code_data))  # Обновляем TTL

            logger.warning(f"Invalid verification code for user {user_id}")
            return False

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse verification code data: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to verify verification code: {e}")
        return False


def delete_verification_code(user_id: int, operation: str) -> bool:
    """
    Удаление кода подтверждения из Redis.

    Args:
        user_id: ID пользователя
        operation: Тип операции

    Returns:
        True если удалено, иначе False
    """
    try:
        global redis_client
        redis_client = get_redis_client()
        redis_key = f"verification_code:{user_id}:{operation}"

        deleted = redis_client.delete(redis_key)
        if deleted:
            logger.info(f"Verification code deleted for user {user_id}, operation: {operation}")
        return deleted > 0

    except Exception as e:
        logger.error(f"Failed to delete verification code: {e}")
        return False


def send_verification_email(email: str, code: str, operation: str) -> bool:
    """Отправляет код подтверждения на email.

    Returns:
        bool: True если успешно, False при ошибке
    """
    url = f"{current_app.config['INTERNAL_NOTIFICATION_SERVICE_URL']}/send-verification"
    payload = {
        "email": email,
        "code": code,
        "operation": operation
    }

    try:
        headers = {
            'X-API-Key': current_app.config['INTERNAL_API_KEY'],
            'User-Agent': 'AuthService/1.0'
        }
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()

        result = resp.json()
        return result.get("status") == "queued"

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Email service request failed: {e}")
        return False
    except Exception as e:
        current_app.logger.error(f"Unexpected error in send_verification_email: {e}")
        return False


def get_account_by_public_id(public_id: str = None, email: str = None) -> Optional[Dict[str, Any]]:
    """
    Получение информации об аккаунте по public_id или email.

    Args:
        public_id: Публичный идентификатор аккаунта
        email: Email аккаунта

    Returns:
        Словарь с информацией об аккаунте или None если аккаунт не найден

    Raises:
        ValueError: Если не передан ни public_id, ни email
    """
    if not public_id and not email:
        raise ValueError("Either public_id or email must be provided")

    try:
        account = None

        # Ищем по public_id (приоритет ибо четко)
        if public_id:
            account = Account.query.filter_by(public_id=public_id).first()
            logger.info(f"Searching account by public_id: {public_id}")

        # Если не нашли по public_id или public_id не передан, ищем по email
        if not account and email:
            account = Account.query.filter_by(email=email).first()
            logger.info(f"Searching account by email: {email}")

        if not account:
            logger.warning(f"Account not found. public_id: {public_id}, email: {email}")
            return None

        # Формируем безопасный словарь с информацией (без пароля и других чувствительных данных)
        account_info = {
            'id': account.id,
            'username': account.username,
            'email': account.email,
            'is_verified': account.is_verified,
            'created_at': account.created_at.isoformat() if account.created_at else None,
            'public_id': account.public_id,
            'two_factor_enabled': account.two_factor_enabled,
            'failed_login_attempts': account.failed_login_attempts,
            'locked_until': account.locked_until.isoformat() if account.locked_until else None,
            'last_failed_login': account.last_failed_login.isoformat() if account.last_failed_login else None
        }

        logger.info(f"Account info retrieved. public_id: {account.public_id}, email: {account.email}")
        return account_info

    except Exception as e:
        logger.error(f"Error retrieving account. public_id: {public_id}, email: {email}: {e}", exc_info=True)
        return None


def create_jwt_tokens(account_id: int, public_id: str) -> Dict[str, str]:
    """
    Создание JWT токенов (access и refresh).

    Args:
        account_id: ID аккаунта в БД
        public_id: Публичный ID аккаунта

    Returns:
        Словарь с access и refresh токенами
    """
    now = datetime.now()
    access_expires = now + timedelta(seconds=current_app.config['JWT_ACCESS_TOKEN_EXPIRES'])
    refresh_expires = now + timedelta(seconds=current_app.config['JWT_REFRESH_TOKEN_EXPIRES'])

    access_payload = {
        'type': 'access',
        'account_id': account_id,
        'public_id': public_id,
        'exp': access_expires.timestamp(),
        'iat': now.timestamp()
    }

    refresh_payload = {
        'type': 'refresh',
        'account_id': account_id,
        'public_id': public_id,
        'exp': refresh_expires.timestamp(),
        'iat': now.timestamp()
    }

    access_token = jwt.encode(
        access_payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

    refresh_token = jwt.encode(
        refresh_payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }


def verify_jwt_token(token: str, token_type: str = 'access') -> Optional[Dict]:
    """
    Верификация JWT токена.

    Args:
        token: JWT токен
        token_type: Тип токена (access или refresh)

    Returns:
        Распарсенный payload или None если токен невалидный
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )

        # Проверяем тип токена
        if payload.get('type') != token_type:
            logger.warning(f"Wrong token type: expected {token_type}, got {payload.get('type')}")
            return None

        # Проверяем срок действия
        if datetime.now().timestamp() > payload.get('exp', 0):
            logger.warning("Token expired")
            return None

        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None


def hash_string(data: str) -> str:
    """
    Хеширование строки с использованием SHA256.

    Args:
        data: Строка для хеширования

    Returns:
        Hex-строка хеша
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def create_user_session(account_id: int, refresh_token: str, user_agent: str) -> Optional[Dict[str, Any]]:
    """
    Создание сессии пользователя в БД.

    Args:
        account_id: ID аккаунта
        refresh_token: Refresh токен
        user_agent: User-Agent браузера

    Returns:
        Информация о созданной сессии или None при ошибке
    """
    try:
        from .models import db, UserSession, Account

        # Проверяем лимит сессий
        max_sessions = current_app.config['MAX_SESSIONS_PER_USER']
        session_count = UserSession.query.filter_by(account_id=account_id, is_active=True).count()

        if session_count >= max_sessions:
            # Находим и удаляем самую старую активную сессию
            oldest_session = UserSession.query.filter_by(
                account_id=account_id,
                is_active=True
            ).order_by(UserSession.created_at.asc()).first()

            if oldest_session:
                db.session.delete(oldest_session)
                logger.info(f"Removed oldest session {oldest_session.session_id} for account {account_id}")

        # Создаем новую сессию
        session_id = secrets.token_urlsafe(32)
        refresh_token_hash = hash_string(refresh_token)
        user_agent_hash = hash_string(user_agent)

        # Срок действия сессии (совпадает с refresh токеном)
        expires_at = datetime.now() + timedelta(
            seconds=current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        )

        session = UserSession(
            account_id=account_id,
            session_id=session_id,
            refresh_token_hash=refresh_token_hash,
            user_agent_hash=user_agent_hash,
            expires_at=expires_at,
            user_agent_original=user_agent[:500] if user_agent else None
        )

        db.session.add(session)
        db.session.commit()

        logger.info(f"Created session {session_id} for account {account_id}")

        return {
            'session_id': session_id,
            'created_at': session.created_at,
            'expires_at': session.expires_at
        }

    except Exception as e:
        logger.error(f"Failed to create user session: {e}", exc_info=True)
        db.session.rollback()
        return None


def verify_session(session_id: str, refresh_token: str, user_agent: str) -> Optional[Dict[str, Any]]:
    """
    Проверка сессии пользователя.

    Args:
        session_id: ID сессии
        refresh_token: Refresh токен
        user_agent: User-Agent браузера

    Returns:
        Информация о сессии или None если сессия невалидна
    """
    try:
        from .models import UserSession

        session = UserSession.query.filter_by(
            session_id=session_id,
            is_active=True
        ).first()

        if not session:
            logger.warning(f"Session not found: {session_id}")
            return None

        # Проверяем срок действия
        if datetime.now() > session.expires_at:
            session.is_active = False
            db.session.commit()
            logger.info(f"Session expired: {session_id}")
            return None

        # Проверяем refresh токен
        refresh_token_hash = hash_string(refresh_token)
        if refresh_token_hash != session.refresh_token_hash:
            logger.warning(f"Invalid refresh token for session: {session_id}")
            return None

        # Проверяем user-agent
        user_agent_hash = hash_string(user_agent)
        if user_agent_hash != session.user_agent_hash:
            logger.warning(f"User-Agent mismatch for session: {session_id}")
            return None

        # Обновляем время последнего использования
        session.last_used = datetime.now()
        db.session.commit()

        return {
            'account_id': session.account_id,
            'session_id': session_id,
            'created_at': session.created_at,
            'last_used': session.last_used
        }

    except Exception as e:
        logger.error(f"Error verifying session: {e}", exc_info=True)
        return None


def set_session_cookie(response, session_id: str, access_token: str):
    """
    Установка сессионной куки.

    Args:
        response: Flask response object
        session_id: ID сессии
        access_token: Access токен
    """
    from flask import current_app

    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    cookie_domain = current_app.config['SESSION_COOKIE_DOMAIN']
    secure = current_app.config['SESSION_COOKIE_SECURE']
    httponly = current_app.config['SESSION_COOKIE_HTTPONLY']
    samesite = current_app.config['SESSION_COOKIE_SAMESITE']

    # Сохраняем session_id и access_token в куке
    cookie_value = f"{session_id}:{access_token}"

    # Параметры для set_cookie
    cookie_kwargs = {
        'key': cookie_name,
        'value': cookie_value,
        'max_age': current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
        'secure': secure,
        'httponly': httponly,
        'samesite': samesite,
        'path': '/'
    }

    # Добавляем domain только если он указан и не None
    if cookie_domain and cookie_domain != 'None' and cookie_domain != '':
        cookie_kwargs['domain'] = cookie_domain

    response.set_cookie(**cookie_kwargs)

    current_app.logger.info(f"Cookie set: {cookie_name}, domain={cookie_domain}")


def get_session_from_cookie(request) -> Optional[Dict[str, str]]:
    """
    Извлечение сессии из куки.

    Args:
        request: Flask request object

    Returns:
        Словарь с session_id и access_token или None
    """
    from flask import current_app

    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    cookie_value = request.cookies.get(cookie_name)

    if not cookie_value:
        return None

    parts = cookie_value.split(':', 1)
    if len(parts) != 2:
        return None

    return {
        'session_id': parts[0],
        'access_token': parts[1]
    }


def invalidate_session(session_id: str):
    """
    Инвалидация сессии.

    Args:
        session_id: ID сессии для инвалидации
    """
    try:
        from .models import db, UserSession

        session = UserSession.query.filter_by(session_id=session_id).first()
        if session:
            session.is_active = False
            db.session.commit()
            logger.info(f"Session invalidated: {session_id}")

    except Exception as e:
        logger.error(f"Error invalidating session: {e}", exc_info=True)
        db.session.rollback()


def invalidate_all_sessions(account_id: int):
    """
    Инвалидация всех сессий пользователя.

    Args:
        account_id: ID аккаунта
    """
    try:
        from .models import db, UserSession

        UserSession.query.filter_by(
            account_id=account_id,
            is_active=True
        ).update({'is_active': False})

        db.session.commit()
        logger.info(f"All sessions invalidated for account: {account_id}")

    except Exception as e:
        logger.error(f"Error invalidating all sessions: {e}", exc_info=True)
        db.session.rollback()


def is_session_valid(session_id: str, access_token: str) -> bool:
    """
    Проверка валидности сессии.

    Args:
        session_id: ID сессии
        access_token: Access токен

    Returns:
        True если сессия валидна, иначе False
    """
    try:
        from .models import UserSession

        # Находим сессию
        session = UserSession.query.filter_by(
            session_id=session_id,
            is_active=True
        ).first()

        if not session:
            logger.debug(f"Session not found or inactive: {session_id}")
            return False

        # Проверяем срок действия
        if datetime.now() > session.expires_at:
            logger.debug(f"Session expired: {session_id}")
            # Помечаем как неактивную
            session.is_active = False
            db.session.commit()
            return False

        # Проверяем access токен
        token_payload = verify_jwt_token(access_token, token_type='access')
        if not token_payload:
            logger.debug(f"Invalid access token for session: {session_id}")
            return False

        # Проверяем что токен принадлежит владельцу сессии
        if token_payload.get('account_id') != session.account_id:
            logger.debug(f"Token account_id mismatch for session: {session_id}")
            return False

        # Обновляем время последнего использования
        session.last_used = datetime.now()
        db.session.commit()

        logger.debug(f"Session validated: {session_id[:10]}...")
        return True

    except Exception as e:
        logger.error(f"Error validating session {session_id[:10]}...: {e}")
        return False