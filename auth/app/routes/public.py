import re
from datetime import datetime, timedelta
from functools import wraps
from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, current_app, jsonify, make_response, g
from ..limiter import limiter
from ..models import db, Account, UserSession
from ..utils import create_verification_code, validate_password_strength, send_verification_email, set_session_cookie, \
    create_user_session, create_jwt_tokens, is_session_valid, clear_session_cookie, delete_session_by_id, \
    delete_all_sessions_by_account_id, get_session_account_id, get_session_from_cookie, hash_string, \
    verify_code_for_operation, confirm_registration, issue_session_for_account, change_account_password, \
    delete_verification_code, delete_account_from_db

bp = Blueprint('public', __name__)

# Проверки никнейма и почты
USERNAME_REGEX = re.compile(r'^[\w-]{3,12}$', re.UNICODE)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def require_valid_session_cookie(f):
    """
    Декоратор для проверки валидности сессии через куки.
    Ожидает куку 'session_token' в формате: session_id:access_token
    Для публичных эндпоинтов.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Получаем сессию из куки
            session_data = get_session_from_cookie(request)

            if not session_data:
                current_app.logger.warning("Missing or invalid session_token cookie")
                return jsonify({
                    "message": "Session required",
                    "detail": "Missing session cookie. Please login first."
                }), 401

            session_id = session_data['session_id']
            access_token = session_data['access_token']

            # Проверяем сессию
            if not is_session_valid(session_id, access_token):
                current_app.logger.info(f"Invalid session from cookies: {session_id[:10]}...")
                return jsonify({
                    "message": "Invalid session",
                    "detail": "Session is invalid or expired. Please login again."
                }), 401

            # Сохраняем данные сессии и токены в g
            g.session_data = {
                'session_id': session_id,
                'access_token': access_token,
                'session_cookie': f"{session_id}:{access_token}"
            }

            # Сохраняем отдельно токены для удобного доступа
            g.session_id = session_id
            g.access_token = access_token

            current_app.logger.info(f"Session validated from cookies for: {session_id[:10]}...")
            return f(*args, **kwargs)

        except Exception as e:
            current_app.logger.error(f"Error validating session from cookies: {e}", exc_info=True)
            return jsonify({
                "message": "Session validation failed",
                "detail": "Internal server error during session validation"
            }), 500

    return decorated


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

        # Отправка кода подтверждения с типом операции 'register'
        try:
            # Создаем и сохраняем код подтверждения в Redis
            verification_code = create_verification_code(
                user_id=account.id,
                operation='registration',
                ttl_minutes=10
            )

            if verification_code:
                # Попытка отправки кода подтверждения на email
                email_sent = send_verification_email(
                    email=email,
                    code=verification_code,
                    operation='registration'
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
            # Отправляем код верификации для подтверждения email с типом операции 'register'
            current_app.logger.info(f"Account not verified, sending code for: {account.email}")

            verification_code = create_verification_code(
                user_id=account.id,
                operation='registration',
                ttl_minutes=10
            )

            if verification_code:
                email_sent = send_verification_email(
                    email=account.email,
                    code=verification_code,
                    operation='registration'
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
            # Отправляем код 2FA с типом операции 'login'
            current_app.logger.info(f"2FA required for: {account.email}")

            verification_code = create_verification_code(
                user_id=account.id,
                operation='login',
                ttl_minutes=10
            )

            if verification_code:
                email_sent = send_verification_email(
                    email=account.email,
                    code=verification_code,
                    operation='login'
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
        # Сначала создаем сессию без токенов
        session_info = create_user_session(
            account_id=account.id,
            refresh_token="",  # Временное значение
            user_agent=user_agent
        )

        if not session_info:
            return jsonify({"message": "Failed to create session"}), 500

        # Создаем JWT токены с session_id
        tokens = create_jwt_tokens(
            account_id=account.id,
            public_id=account.public_id,
            session_id=session_info['session_id']  # Ключевое изменение!
        )

        # Обновляем refresh_token_hash в сессии
        session = UserSession.query.filter_by(session_id=session_info['session_id']).first()
        if session:
            session.refresh_token_hash = hash_string(tokens['refresh_token'])
            db.session.commit()

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
            },
            "tokens": {
                "access_token": tokens['access_token'],
                "refresh_token": tokens['refresh_token'],
                "access_expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                "refresh_expires_in": current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
            }
        }

        response = make_response(jsonify(response_data), 200)

        # Устанавливаем сессионную куку
        set_session_cookie(response, session_info['session_id'], tokens['access_token'])

        current_app.logger.info(f"Successful login for: {account.email}, session: {session_info['session_id'][:10]}...")
        return response

    except Exception as e:
        current_app.logger.error(f"Unexpected error in login: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/verify", methods=["POST"])
@limiter.limit("5 per 2 minutes, 20 per hour, 3 per minute")
def verify():
    """Подтверждение операций (регистрация, сброс пароля, удаление аккаунта, 2FA)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data"}), 400

        # Обязательные поля для всех операций
        operation = data.get("operation")
        code = data.get("code")

        if not operation or not code:
            return jsonify({"message": "Missing operation or code"}), 400

        # Проверяем валидность операции
        valid_operations = ['registration', 'login', 'reset', 'delete']
        if operation not in valid_operations:
            return jsonify({
                "message": "Invalid operation",
                "detail": f"Valid operations: {', '.join(valid_operations)}"
            }), 400

        account = None
        email = None

        # Определяем источник информации об аккаунте в зависимости от операции
        if operation in ['reset', 'delete']:
            # Для reset и delete - используем сессионные куки
            session_data = get_session_from_cookie(request)
            if not session_data:
                return jsonify({
                    "message": "Session required",
                    "detail": "Session cookie is required for this operation"
                }), 401

            # Проверяем сессию
            if not is_session_valid(session_data['session_id'], session_data['access_token']):
                return jsonify({
                    "message": "Invalid session",
                    "detail": "Session is invalid or expired"
                }), 401

            # Получаем account_id из сессии
            account_id = get_session_account_id(session_data['session_id'])
            if not account_id:
                return jsonify({"message": "Account not found for session"}), 404

            # Находим аккаунт
            account = Account.query.get(account_id)
            if not account:
                return jsonify({"message": "Account not found"}), 404

        else:
            # Для registration и login - получаем email из JSON
            email = data.get("email")
            if not email:
                return jsonify({"message": "Email is required for this operation"}), 400

            # Находим аккаунт по email
            account = Account.query.filter_by(email=email).first()
            if not account:
                # Для безопасности возвращаем общий ответ
                current_app.logger.warning(f"Verify attempt for non-existent email: {email}")
                return jsonify({"message": "Invalid verification code"}), 400

        if not account:
            return jsonify({"message": "Account not found"}), 404

        # Проверяем код подтверждения
        if not verify_code_for_operation(account.id, code, operation):
            return jsonify({"message": "Invalid verification code"}), 400

        current_app.logger.info(f"Code verified for account {account.id}, operation: {operation}")

        # Выполняем соответствующую операцию
        result = None

        if operation == 'registration':
            # Подтверждаем регистрацию
            updated_account = confirm_registration(account.id)
            if not updated_account:
                return jsonify({"message": "Failed to confirm registration"}), 500

            # Выдаем сессию
            user_agent = request.headers.get('User-Agent', '')
            session_data = issue_session_for_account(updated_account, user_agent)

            if session_data:
                # Создаем ответ и устанавливаем куки
                response_data = {
                    "message": "Registration confirmed successfully",
                    "account": {
                        "username": updated_account.username,
                        "email": updated_account.email,
                        "public_id": updated_account.public_id,
                        "is_verified": updated_account.is_verified
                    },
                    "session": {
                        "session_id": session_data['session_info']['session_id'],
                        "created_at": session_data['session_info']['created_at'].isoformat(),
                        "expires_at": session_data['session_info']['expires_at'].isoformat()
                    },
                    "tokens": {
                        "access_token": session_data['tokens']['access_token'],
                        "refresh_token": session_data['tokens']['refresh_token'],
                        "access_expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                        "refresh_expires_in": current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
                    }
                }

                response = make_response(jsonify(response_data), 200)
                set_session_cookie(response, session_data['session_info']['session_id'],
                                   session_data['tokens']['access_token'])

                current_app.logger.info(f"Registration confirmed and session created for: {updated_account.email}")
                return response
            else:
                return jsonify({
                    "message": "Registration confirmed but failed to create session",
                    "detail": "Please login manually"
                }), 201

        elif operation == 'login':
            # Обработка 2FA
            # Определяем, нужно ли включить 2FA или проверить его
            if not account.two_factor_enabled:
                # Включаем 2FA (но не выдаем сессию)
                from ..utils import handle_2fa_verification
                twofa_result = handle_2fa_verification(account, enable_2fa=True)

                if twofa_result['success']:
                    return jsonify({
                        "message": "Two-factor authentication enabled",
                        "detail": "2FA has been enabled for your account. Please login again.",
                        "two_factor_enabled": True
                    }), 200
                else:
                    return jsonify({
                        "message": "Failed to enable two-factor authentication",
                        "detail": twofa_result['message']
                    }), 500
            else:
                # 2FA уже включен - проверяем и выдаем сессию
                from ..utils import handle_2fa_verification
                twofa_result = handle_2fa_verification(account, enable_2fa=False)

                if twofa_result['success'] and twofa_result['requires_session']:
                    # Создаем ответ и устанавливаем куки
                    response_data = {
                        "message": "Two-factor authentication successful",
                        "account": {
                            "username": account.username,
                            "email": account.email,
                            "public_id": account.public_id,
                            "is_verified": account.is_verified,
                            "two_factor_enabled": account.two_factor_enabled
                        },
                        "session": {
                            "session_id": twofa_result['session_data']['session_info']['session_id'],
                            "created_at": twofa_result['session_data']['session_info']['created_at'].isoformat(),
                            "expires_at": twofa_result['session_data']['session_info']['expires_at'].isoformat()
                        },
                        "tokens": {
                            "access_token": twofa_result['session_data']['tokens']['access_token'],
                            "refresh_token": twofa_result['session_data']['tokens']['refresh_token'],
                            "access_expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                            "refresh_expires_in": current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
                        }
                    }

                    response = make_response(jsonify(response_data), 200)
                    set_session_cookie(response,
                                       twofa_result['session_data']['session_info']['session_id'],
                                       twofa_result['session_data']['tokens']['access_token'])

                    current_app.logger.info(f"2FA login successful for: {account.email}")
                    return response
                else:
                    return jsonify({
                        "message": "Two-factor authentication failed",
                        "detail": twofa_result['message']
                    }), 401

        elif operation == 'reset':
            # Изменение пароля
            new_password = data.get("new_password")
            if not new_password:
                return jsonify({"message": "New password is required"}), 400

            # Проверяем надежность пароля
            is_valid, message = validate_password_strength(new_password)
            if not is_valid:
                return jsonify({"message": message}), 400

            # Изменяем пароль
            if change_account_password(account.id, new_password):
                # Удаляем код подтверждения (после успешного использования)
                delete_verification_code(account.id, 'reset')

                current_app.logger.info(f"Password reset successful for: {account.email}")
                return jsonify({
                    "message": "Password reset successful",
                    "detail": "You can now login with your new password"
                }), 200
            else:
                return jsonify({"message": "Failed to reset password"}), 500

        elif operation == 'delete':
            # Удаление аккаунта
            if delete_account_from_db(account.id):
                # Очищаем куки
                response = make_response(jsonify({
                    "message": "Account deleted successfully",
                    "detail": "Your account has been permanently deleted"
                }), 200)

                clear_session_cookie(response)

                current_app.logger.info(f"Account deleted: {account.email}")
                return response
            else:
                return jsonify({"message": "Failed to delete account"}), 500

        return jsonify({"message": "Unknown operation"}), 400

    except Exception as e:
        current_app.logger.error(f"Unexpected error in verify: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/2fa", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def tfa():
    """Отправка кода двухфакторной аутентификации"""
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
            # Для безопасности не раскрываем, существует ли аккаунт
            current_app.logger.warning(f"2FA request for non-existent email: {email}")
            return jsonify({
                "message": "If an account exists with this email, a verification code has been sent"
            }), 200

        # Создаем и отправляем код подтверждения с типом операции 'login'
        verification_code = create_verification_code(
            user_id=account.id,
            operation='login',
            ttl_minutes=5
        )

        if not verification_code:
            current_app.logger.error(f"Failed to create verification code for 2FA: {account.id}")
            return jsonify({"message": "Failed to generate verification code"}), 500

        email_sent = send_verification_email(
            email=account.email,
            code=verification_code,
            operation='login'
        )

        if email_sent:
            current_app.logger.info(f"2FA code sent to email for: {account.email}")
            return jsonify({
                "message": "If an account exists with this email, a verification code has been sent",
                "detail": "Please check your email for the verification code"
            }), 200
        else:
            current_app.logger.warning(f"Failed to send 2FA email for: {account.email}")
            return jsonify({
                "message": "Failed to send verification email",
                "detail": "Please try again later"
            }), 500

    except Exception as e:
        current_app.logger.error(f"Unexpected error in 2fa: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/logout", methods=["POST"])
@limiter.limit("20 per minute, 50 per hour")
@require_valid_session_cookie
def logout():
    """Выход из текущей сессии"""
    try:
        # Получаем session_id из g (уже проверено декоратором)
        session_id = g.session_id

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
        # Получаем session_id из g (уже проверено декоратором)
        session_id = g.session_id

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
            # Для безопасности не раскрываем, существует ли аккаунт
            current_app.logger.warning(f"Reset request for non-existent email: {email}")
            return jsonify({
                "message": "If an account exists with this email, a verification code has been sent"
            }), 200

        # Проверяем, что аккаунт верифицирован
        if not account.is_verified:
            return jsonify({
                "message": "Account not verified",
                "detail": "Please verify your account first"
            }), 403

        # Создаем и отправляем код подтверждения с типом операции 'reset'
        verification_code = create_verification_code(
            user_id=account.id,
            operation='reset',
            ttl_minutes=10
        )

        if not verification_code:
            current_app.logger.error(f"Failed to create verification code for reset: {account.id}")
            return jsonify({"message": "Failed to generate verification code"}), 500

        email_sent = send_verification_email(
            email=account.email,
            code=verification_code,
            operation='reset'
        )

        if email_sent:
            current_app.logger.info(f"Reset code sent to email for: {account.email}")
            return jsonify({
                "message": "If an account exists with this email, a verification code has been sent",
                "detail": "Please check your email for the verification code"
            }), 200
        else:
            current_app.logger.warning(f"Failed to send reset email for: {account.email}")
            return jsonify({
                "message": "Failed to send verification email",
                "detail": "Please try again later"
            }), 500

    except Exception as e:
        current_app.logger.error(f"Unexpected error in reset: {e}", exc_info=True)
        return jsonify({"message": "Internal error"}), 500


@bp.route("/delete", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
@require_valid_session_cookie
def delete():
    """Запрос на удаление аккаунта (отправка кода подтверждения)"""
    try:
        # Получаем session_id из g (уже проверено декоратором)
        session_id = g.session_id

        # Получаем account_id по session_id
        account_id = get_session_account_id(session_id)

        if not account_id:
            return jsonify({"message": "Invalid session"}), 401

        # Находим аккаунт
        account = Account.query.get(account_id)
        if not account:
            return jsonify({"message": "Account not found"}), 404

        # Создаем и отправляем код подтверждения с типом операции 'delete'
        verification_code = create_verification_code(
            user_id=account.id,
            operation='delete',
            ttl_minutes=10
        )

        if not verification_code:
            current_app.logger.error(f"Failed to create verification code for delete: {account.id}")
            return jsonify({"message": "Failed to generate verification code"}), 500

        email_sent = send_verification_email(
            email=account.email,
            code=verification_code,
            operation='delete'
        )

        if email_sent:
            current_app.logger.info(f"Delete confirmation code sent to email for: {account.email}")
            return jsonify({
                "message": "Verification code sent to email",
                "detail": "Please check your email for the verification code to confirm account deletion"
            }), 200
        else:
            current_app.logger.warning(f"Failed to send delete confirmation email for: {account.email}")
            return jsonify({
                "message": "Failed to send verification email",
                "detail": "Please try again later"
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