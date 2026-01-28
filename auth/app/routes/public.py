import re
from datetime import datetime, timedelta

from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, current_app, jsonify, make_response
from ..limiter import limiter
from ..models import db, Account
from ..utils import create_verification_code, validate_password_strength, send_verification_email, set_session_cookie, \
    create_user_session, create_jwt_tokens

bp = Blueprint('public', __name__)

# Проверки никнейма и почты
USERNAME_REGEX = re.compile(r'^[\w-]{3,12}$', re.UNICODE)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


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

        # Отправка кода подтверждения
        try:
            # Создаем и сохраняем код подтверждения в Redis
            verification_code = create_verification_code(
                user_id=account.id,
                operation='register',
                ttl_minutes=10
            )

            if verification_code:
                # Попытка отправки кода подтверждения на email
                email_sent = send_verification_email(
                    email=email,
                    code=verification_code,
                    operation='register'
                )

                if email_sent:
                    # Успешная отправка email
                    current_app.logger.info(
                        f"Verification code sent to email for user {account.id} ({email})"
                    )

                    return jsonify({
                        "message": "Registration Success",
                        "detail": "Verification code sent to email"
                    }), 201
                else:
                    # Ошибка отправки email
                    current_app.logger.warning(
                        f"Failed to send verification email for user {account.id} ({email}). "
                        f"Code for debugging: {verification_code}"
                    )

                    return jsonify({
                        "message": "Registration Success",
                        "detail": "Account created but verification email could not be sent. Please use resend verification."
                    }), 201
            else:
                current_app.logger.error(f"Failed to create verification code for user {account.id}")
                # Аккаунт создан, но код не создан
                return jsonify({
                    "message": "Registration Success",
                    "detail": "Account created but verification code could not be generated. Please use resend verification."
                }), 201

        except Exception as e:
            current_app.logger.error(f"Failed to send verification code: {e}", exc_info=True)
            # Аккаунт создан, но произошла ошибка при отправке кода
            return jsonify({
                "message": "Registration Success",
                "detail": "Account created but verification email failed. Please use resend verification."
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
            # Отправляем код верификации для подтверждения email
            current_app.logger.info(f"Account not verified, sending code for: {account.email}")

            verification_code = create_verification_code(
                user_id=account.id,
                operation='login_verify_email',
                ttl_minutes=10
            )

            if verification_code:
                email_sent = send_verification_email(
                    email=account.email,
                    code=verification_code,
                    operation='login_verify_email'
                )

                if email_sent:
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
            else:
                return jsonify({
                    "message": "Account not verified",
                    "detail": "Failed to generate verification code",
                    "requires_verification": True,
                    "verification_type": "email"
                }), 200

        # Проверяем двухфакторную аутентификацию
        if account.two_factor_enabled:
            # Отправляем код 2FA
            current_app.logger.info(f"2FA required for: {account.email}")

            verification_code = create_verification_code(
                user_id=account.id,
                operation='two_factor_auth',
                ttl_minutes=5
            )

            if verification_code:
                email_sent = send_verification_email(
                    email=account.email,
                    code=verification_code,
                    operation='two_factor_auth'
                )

                if email_sent:
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
            else:
                return jsonify({
                    "message": "Two-factor authentication required",
                    "detail": "Failed to generate verification code",
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
def verify():
    pass


@bp.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per 5 minutes, 10 per hour, 2 per 2 minutes")
def resend_verification():
    pass


@bp.route("/logout", methods=["POST"])
@limiter.limit("20 per minute, 50 per hour")
def logout():
    pass


@bp.route("/logout-all", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def logout_all():
    pass


@bp.route("/reset", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def reset():
    pass


@bp.route("/delete", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def delete():
    pass


@bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute, 30 per hour")
def refresh():
    pass


@bp.route('/health')
@limiter.limit("30 per minute, 180 per hour")
def health():
    return "OK", 200