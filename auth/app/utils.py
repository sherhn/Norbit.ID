import secrets
import string
import bcrypt
import json
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
import redis
import logging
import re
import requests
from flask import current_app
from .models import Account

logger = logging.getLogger(__name__)

# Redis клиент
redis_client = None


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