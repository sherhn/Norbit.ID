import re
from datetime import datetime, timedelta
from functools import wraps
from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, current_app, jsonify, make_response, g
from ..limiter import limiter
from ..models import db, Account
from ..utils import create_verification_code, validate_password_strength, send_verification_email, set_session_cookie, \
    create_user_session, create_jwt_tokens, is_session_valid, clear_session_cookie, delete_session_by_id, \
    delete_all_sessions_by_account_id, get_session_account_id, verify_verification_code, delete_verification_code

bp = Blueprint('public', __name__)

# Проверки никнейма и почты
USERNAME_REGEX = re.compile(r'^[\w-]{3,12}$', re.UNICODE)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Определение типов операций для кодов подтверждения
OPERATION_TYPES = {
    'registration': 'register',
    'login_unverified': 'register',  # Для входа без верифицированного аккаунта
    'reset_password': 'reset',
    'delete_account': 'delete',
    'two_factor_auth': 'login'
}


def require_valid_session_cookie(f):
    """
    Декоратор для проверки валидности сессии через куки.
    Ожидает куку 'session_token' в формате: session_id:access_token
    Для публичных эндпоинтов.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Получаем session_token куку
            session_cookie = None

            cookie_header = request.headers.get('Cookie') or request.headers.get('cookie')
            if cookie_header:
                # Парсим куки из заголовка
                for cookie in cookie_header.split(';'):
                    cookie = cookie.strip()
                    if cookie.startswith('session_token='):
                        session_cookie = cookie[len('session_token='):].strip()
                        break

            if not session_cookie:
                current_app.logger.warning("Missing session_token cookie")
                return jsonify({
                    "message": "Session required",
                    "detail": "Missing session cookie. Please login first."
                }), 401

            # Извлекаем session_id и access_token из куки
            # Формат: session_id:access_token
            parts = session_cookie.split(':', 1)
            if len(parts) != 2:
                current_app.logger.warning(f"Invalid session cookie format: {session_cookie[:50]}...")
                return jsonify({
                    "message": "Invalid session",
                    "detail": "Invalid session cookie format"
                }), 400

            session_id, access_token = parts

            # Проверяем сессию
            if not is_session_valid(session_id, access_token):
                current_app.logger.info(f"Invalid session from cookies: {session_id[:10]}...")
                return jsonify({
                    "message": "Invalid session",
                    "detail": "Session is invalid or expired. Please login again."
                }), 401

            # Сохраняем данные сессии в g
            g.session_data = {
                'session_id': session_id,
                'access_token': access_token,
                'session_cookie': session_cookie
            }

            current_app.logger.info(f"Session validated from cookies for: {session_id[:10]}...")
            return f(*args, **kwargs)

        except Exception as e:
            current_app.logger.error(f"Error validating session from cookies: {e}", exc_info=True)
            return jsonify({
                "message": "Session validation failed",
                "detail": "Internal server error during session validation"
            }), 500

    return decorated


def create_and_send_verification_code(account_id: int, email: str, operation: str, ttl_minutes: int = 10) -> bool:
    """
    Универсальная функция для создания и отправки кода подтверждения.

    Args:
        account_id: ID аккаунта
        email: Email для отправки
        operation: Тип операции (register, reset, delete, login)
        ttl_minutes: Время жизни кода в минутах

    Returns:
        True если успешно, False при ошибке
    """
    try:
        # Создаем код подтверждения
        verification_code = create_verification_code(
            user_id=account_id,
            operation=operation,
            ttl_minutes=ttl_minutes
        )

        if not verification_code:
            current_app.logger.error(f"Failed to create verification code for user {account_id}")
            return False

        # Отправляем код на email
        email_sent = send_verification_email(
            email=email,
            code=verification_code,
            operation=operation
        )

        if not email_sent:
            current_app.logger.warning(f"Failed to send verification email for user {account_id}")
            # Для отладки можно залогировать код
            current_app.logger.info(f"Generated code for debugging (user {account_id}): {verification_code}")
            return False

        current_app.logger.info(f"Verification code sent for {operation} operation to user {account_id}")
        return True

    except Exception as e:
        current_app.logger.error(f"Error in create_and_send_verification_code: {e}", exc_info=True)
        return False


@bp.route("/registration", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def registration():
    """Регистрация"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return jsonify({"message": "Missing Fields"}, 400)

        if not USERNAME_REGEX.match(username):
            return jsonify({"message": "Invalid Username"}, 400)

        if not EMAIL_REGEX.match(email):
            return jsonify({"message": "Invalid Email"}, 400)

        is_valid_password, password_message = validate_password_strength(password)
        if not is_valid_password:
            return jsonify({"message": password_message}), 400

        try:
            valid = validate_email(email, check_deliverability=False)
            email = valid.normalized
        except EmailNotValidError:
            return jsonify({"message": "Invalid Email"}, 400)

        exists = db.session.query(db.exists().where(Account.email == email)).scalar()
        if exists:
            return jsonify({"message": "User Already Exists"}, 409)

        account = Account(username=username, email=email)
        account.set_password(password)
        db.session.add(account)

        try:
            db.session.commit()
            # После успешного коммита account.id становится доступным
            current_app.logger.info(f"Account created with ID: {account.id}")
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration commit failed: {e}", exc_info=True)
            return jsonify({"message": "Registration Failed"}), 500

        # Используем универсальную функцию для отправки кода подтверждения
        code_sent = create_and_send_verification_code(
            account_id=account.id,
            email=email,
            operation='register',  # Тип операции для регистрации
            ttl_minutes=10
        )

        if code_sent:
            return jsonify({
                "message": "Registration Success",
                "detail": "Verification code sent to email"
            }), 201
        else:
            # Аккаунт создан, но код не отправлен
            return jsonify({
                "message": "Registration Success",
                "detail": "Account created but verification email could not be sent. Please use resend verification."
            }), 201

    except Exception as e:
        current_app.logger.error(f"Unexpected error in register: {e}", exc_info=True)
        return jsonify({"message": "Internal Error"}), 500


@bp.route("/login", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def login():
    """Аутентификация пользователя"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"message": "Missing email or password"}), 400

        # Находим аккаунт
        account = Account.query.filter_by(email=email).first()
        if not account:
            # Возвращаем ту же ошибку для безопасности
            current_app.logger.warning(f"Login attempt for non-existent email: {email}")
            return jsonify({"message": "Invalid credentials"}), 401

        # Проверяем блокировку
        if account.locked_until and account.locked_until > datetime.now():
            lock_time_remaining = (account.locked_until - datetime.now()).seconds
            current_app.logger.warning(f"Account locked for {account.email}, time remaining: {lock_time_remaining}s")
            return jsonify({
                "message": "Account is temporarily locked",
                "retry_after": lock_time_remaining
            }), 423

        # Проверяем пароль
        if not account.check_password(password):
            # Увеличиваем счетчик неудачных попыток
            account.failed_login_attempts += 1
            account.last_failed_login = datetime.now()

            # Блокируем аккаунт после 5 неудачных попыток
            if account.failed_login_attempts >= 5:
                account.locked_until = datetime.now() + timedelta(minutes=15)
                current_app.logger.warning(f"Account locked due to multiple failed attempts: {account.email}")

            db.session.commit()

            current_app.logger.warning(f"Failed login attempt for {account.email}")
            return jsonify({"message": "Invalid credentials"}), 401

        # Сбрасываем счетчик неудачных попыток при успешном входе
        account.failed_login_attempts = 0
        account.locked_until = None
        db.session.commit()

        # Получаем User-Agent
        user_agent = request.headers.get('User-Agent', '')

        # Проверяем, нужна ли верификация
        if not account.is_verified:
            # Используем универсальную функцию для отправки кода верификации
            code_sent = create_and_send_verification_code(
                account_id=account.id,
                email=account.email,
                operation='register',  # Для неверифицированного аккаунта используем register
                ttl_minutes=10
            )

            if code_sent:
                return jsonify({
                    "message": "Account not verified",
                    "detail": "Verification code sent to email",
                    "requires_verification": True,
                    "verification_type": "email"
                }), 200
            else:
                return jsonify({
                    "message": "Account not verified",
                    "detail": "Failed to send verification email. Please try again.",
                    "requires_verification": True,
                    "verification_type": "email"
                }), 200

        # Проверяем двухфакторную аутентификацию
        if account.two_factor_enabled:
            # Отправляем код 2FA через универсальную функцию
            code_sent = create_and_send_verification_code(
                account_id=account.id,
                email=account.email,
                operation='login',  # Для двухфакторной аутентификации используем login
                ttl_minutes=5
            )

            if code_sent:
                return jsonify({
                    "message": "Two-factor authentication required",
                    "detail": "Verification code sent to email",
                    "requires_verification": True,
                    "verification_type": "two_factor"
                }), 200
            else:
                return jsonify({
                    "message": "Two-factor authentication required",
                    "detail": "Failed to send verification code. Please try again.",
                    "requires_verification": True,
                    "verification_type": "two_factor"
                }), 200

        # Если все проверки пройдены - создаем сессию
        tokens = create_jwt_tokens(account.id, account.public_id)

        session_info = create_user_session(
            account_id=account.id,
            refresh_token=tokens['refresh_token'],
            user_agent=user_agent
        )

        if not session_info:
            return jsonify({"message": "Failed to create session"}), 500

        # Создаем ответ и устанавливаем куки
        response_data = {
            "message": "Login successful",
            "account": {
                "username": account.username,
                "email": account.email,
                "public_id": account.public_id,
                "is_verified": account.is_verified
            },
            "session": {
                "session_id": session_info['session_id'],
                "created_at": session_info['created_at'].isoformat(),
                "expires_at": session_info['expires_at'].isoformat()
            }
        }

        response = make_response(jsonify(response_data), 200)

        # Устанавливаем сессионную куку
        set_session_cookie(response, session_info['session_id'], tokens['access_token'])

        current_app.logger.info(f"Successful login for: {account.email}")
        return response

    except Exception as e:
        current_app.logger.error(f"Unexpected error in login: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/verify", methods=["POST"])
@limiter.limit("5 per 2 minutes, 20 per hour, 3 per minute")
@require_valid_session_cookie
def verify():
    pass


@bp.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per 5 minutes, 10 per hour, 2 per 2 minutes")
def resend_verification():
    pass


@bp.route("/2fa", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def tfa():
    """Верификация двухфакторной аутентификации"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        email = data.get("email")
        code = data.get("code")

        if not email or not code:
            return jsonify({"message": "Missing email or code"}), 400

        # Находим аккаунт
        account = Account.query.filter_by(email=email).first()
        if not account:
            current_app.logger.warning(f"2FA attempt for non-existent email: {email}")
            return jsonify({"message": "Invalid credentials"}), 401

        # Проверяем, включена ли двухфакторная аутентификация
        if not account.two_factor_enabled:
            return jsonify({"message": "Two-factor authentication not enabled"}), 400

        # Проверяем код подтверждения
        is_valid = verify_verification_code(
            user_id=account.id,
            code=code,
            operation='login'  # Для двухфакторной аутентификации используем login
        )

        if not is_valid:
            current_app.logger.warning(f"Invalid 2FA code for user: {account.email}")
            return jsonify({"message": "Invalid verification code"}), 401

        # Код верный, удаляем его
        delete_verification_code(account.id, 'login')

        # Получаем User-Agent
        user_agent = request.headers.get('User-Agent', '')

        # Создаем JWT токены и сессию
        tokens = create_jwt_tokens(account.id, account.public_id)

        session_info = create_user_session(
            account_id=account.id,
            refresh_token=tokens['refresh_token'],
            user_agent=user_agent
        )

        if not session_info:
            return jsonify({"message": "Failed to create session"}), 500

        # Создаем ответ и устанавливаем куки
        response_data = {
            "message": "Two-factor authentication successful",
            "account": {
                "username": account.username,
                "email": account.email,
                "public_id": account.public_id,
                "is_verified": account.is_verified
            },
            "session": {
                "session_id": session_info['session_id'],
                "created_at": session_info['created_at'].isoformat(),
                "expires_at": session_info['expires_at'].isoformat()
            }
        }

        response = make_response(jsonify(response_data), 200)

        # Устанавливаем сессионную куку
        set_session_cookie(response, session_info['session_id'], tokens['access_token'])

        current_app.logger.info(f"Successful 2FA login for: {account.email}")
        return response

    except Exception as e:
        current_app.logger.error(f"Unexpected error in tfa: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/logout", methods=["POST"])
@limiter.limit("20 per minute, 50 per hour")
@require_valid_session_cookie
def logout():
    """Выход из текущей сессии"""
    try:
        # Получаем session_token из куки
        session_cookie = None

        cookie_header = request.headers.get('Cookie') or request.headers.get('cookie')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('session_token='):
                    session_cookie = cookie[len('session_token='):].strip()
                    break

        if not session_cookie:
            current_app.logger.warning("No session cookie found for logout")
            return jsonify({
                "message": "No active session",
                "detail": "Already logged out or no session found"
            }), 200  # Возвращаем 200, т.к. пользователь уже "разлогинен"

        # Извлекаем session_id из куки
        parts = session_cookie.split(':', 1)
        if len(parts) != 2:
            # Кука в неправильном формате, все равно очищаем
            response = make_response(jsonify({
                "message": "Session cookie cleared",
                "detail": "Invalid session cookie format"
            }), 200)
            clear_session_cookie(response)
            return response

        session_id, _ = parts

        deleted = delete_session_by_id(session_id)

        if deleted:
            current_app.logger.info(f"Session {session_id[:10]}... deleted from DB")
        else:
            current_app.logger.warning(f"Session {session_id[:10]}... not found in DB")

        # Создаем ответ и очищаем куку
        response = make_response(jsonify({
            "message": "Logged out successfully",
            "detail": "Session terminated and cookie cleared",
            "session_deleted": deleted
        }), 200)

        # Очищаем сессионную куку
        clear_session_cookie(response)

        return response

    except Exception as e:
        current_app.logger.error(f"Error during logout: {e}", exc_info=True)

        # Все равно пытаемся очистить куку
        response = make_response(jsonify({
            "message": "Logout attempted",
            "detail": "Error occurred but cookie cleared",
            "error": str(e)
        }), 200)

        try:
            clear_session_cookie(response)
        except:
            pass

        return response


@bp.route("/logout-all", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
@require_valid_session_cookie
def logout_all():
    """Выход из всех сессий пользователя"""
    try:
        # Получаем session_token из куки
        session_cookie = None

        cookie_header = request.headers.get('Cookie') or request.headers.get('cookie')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('session_token='):
                    session_cookie = cookie[len('session_token='):].strip()
                    break

        if not session_cookie:
            current_app.logger.warning("No session cookie found for logout-all")
            return jsonify({
                "message": "No active session",
                "detail": "Already logged out or no session found"
            }), 200

        # Извлекаем session_id из куки
        parts = session_cookie.split(':', 1)
        if len(parts) != 2:
            # Кука в неправильном формате
            response = make_response(jsonify({
                "message": "Invalid session cookie",
                "detail": "Cannot determine account from invalid cookie"
            }), 400)
            return response

        session_id, _ = parts

        # Получаем account_id по session_id
        account_id = get_session_account_id(session_id)

        if not account_id:
            current_app.logger.warning(f"Cannot find account for session: {session_id[:10]}...")

            # Все равно очищаем куку
            response = make_response(jsonify({
                "message": "Session cookie cleared",
                "detail": "Account not found for session"
            }), 200)
            clear_session_cookie(response)
            return response

        # Удаляем все сессии аккаунта из БД
        deleted = delete_all_sessions_by_account_id(account_id)

        if deleted:
            current_app.logger.info(f"All sessions deleted for account: {account_id}")
        else:
            current_app.logger.warning(f"No sessions found or error deleting for account: {account_id}")

        # Создаем ответ и очищаем куку
        response = make_response(jsonify({
            "message": "Logged out from all devices",
            "detail": "All sessions terminated and cookie cleared",
            "account_id": account_id,
            "all_sessions_deleted": deleted
        }), 200)

        # Очищаем сессионную куку
        clear_session_cookie(response)

        return response

    except Exception as e:
        current_app.logger.error(f"Error during logout-all: {e}", exc_info=True)

        # Все равно пытаемся очистить куку
        response = make_response(jsonify({
            "message": "Logout-all attempted",
            "detail": "Error occurred but cookie cleared",
            "error": str(e)
        }), 200)

        try:
            clear_session_cookie(response)
        except:
            pass

        return response


@bp.route("/reset", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def reset():
    """Запрос на сброс пароля (отправка кода подтверждения)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        email = data.get("email")

        if not email:
            return jsonify({"message": "Missing email"}), 400

        # Находим аккаунт
        account = Account.query.filter_by(email=email).first()
        if not account:
            # Для безопасности не сообщаем, что email не существует
            current_app.logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({
                "message": "If the email exists, a verification code has been sent"
            }), 200

        # Используем универсальную функцию для отправки кода подтверждения
        code_sent = create_and_send_verification_code(
            account_id=account.id,
            email=account.email,
            operation='reset',  # Тип операции для сброса пароля
            ttl_minutes=10
        )

        if code_sent:
            current_app.logger.info(f"Password reset code sent to: {account.email}")
            return jsonify({
                "message": "If the email exists, a verification code has been sent"
            }), 200
        else:
            current_app.logger.error(f"Failed to send password reset code to: {account.email}")
            return jsonify({
                "message": "Failed to send verification code. Please try again."
            }), 500

    except Exception as e:
        current_app.logger.error(f"Unexpected error in reset: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/delete", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def delete():
    """Запрос на удаление аккаунта (отправка кода подтверждения)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"message": "Missing email or password"}), 400

        # Находим аккаунт
        account = Account.query.filter_by(email=email).first()
        if not account:
            current_app.logger.warning(f"Delete attempt for non-existent email: {email}")
            return jsonify({"message": "Invalid credentials"}), 401

        # Проверяем пароль
        if not account.check_password(password):
            current_app.logger.warning(f"Invalid password for delete attempt: {account.email}")
            return jsonify({"message": "Invalid credentials"}), 401

        # Используем универсальную функцию для отправки кода подтверждения
        code_sent = create_and_send_verification_code(
            account_id=account.id,
            email=account.email,
            operation='delete',  # Тип операции для удаления аккаунта
            ttl_minutes=10
        )

        if code_sent:
            current_app.logger.info(f"Account deletion code sent to: {account.email}")
            return jsonify({
                "message": "Verification code sent to email",
                "detail": "Check your email for the verification code to confirm account deletion"
            }), 200
        else:
            current_app.logger.error(f"Failed to send account deletion code to: {account.email}")
            return jsonify({
                "message": "Failed to send verification code. Please try again."
            }), 500

    except Exception as e:
        current_app.logger.error(f"Unexpected error in delete: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute, 30 per hour")
def refresh():
    pass


@bp.route('/health')
@limiter.limit("30 per minute, 180 per hour")
def health():
    return "OK", 200