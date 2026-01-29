from functools import wraps
from flask import Blueprint, request, current_app, jsonify, g
from ..utils import is_session_valid, validate_service_token, \
    delete_session_by_id, delete_all_sessions_by_account_id, get_session_account_id
from ..models import UserSession, db

bp = Blueprint('internal', __name__)


def require_internal_api_key(f):
    """
    Декоратор для проверки валидности внутреннего API ключа.
    Ожидает ключ в заголовке X-Internal-API-Key.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        # Получаем API ключ из заголовка
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            current_app.logger.warning(f"Missing internal API key from {request.remote_addr}")
            return jsonify({"error": "Internal API key required"}), 401

        # Проверяем ключ
        if api_key != current_app.config['INTERNAL_API_KEY']:
            current_app.logger.warning(f"Invalid internal API key from {request.remote_addr}")
            return jsonify({"error": "Invalid internal API key"}), 401

        current_app.logger.info(f"Internal API key validated")
        return f(*args, **kwargs)

    return decorated


def require_internal_token(f):
    """
    Декоратор для проверки валидности токена сервиса.
    Ожидает токен в заголовке X-Service-Token.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        # Получаем токен из заголовка
        service_token = request.headers.get('X-Service-Token')

        if not service_token:
            current_app.logger.warning(f"Missing service token from {request.remote_addr}")
            return jsonify({"error": "Service token required"}), 401

        # Проверяем токен
        token_info = validate_service_token(service_token)
        if not token_info:
            current_app.logger.warning(f"Invalid service token from {request.remote_addr}")
            return jsonify({"error": "Invalid or expired service token"}), 401

        # Сохраняем информацию о сервисе в контексте
        g.service_info = token_info
        current_app.logger.info(f"Service authenticated: {token_info['service_name']}")

        return f(*args, **kwargs)

    return decorated


def require_valid_session(f):
    """
    Декоратор для проверки валидности сессии через JSON.
    Ожидает в JSON: session_id и access_token.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Получаем данные из JSON
            data = request.get_json()
            if not data:
                current_app.logger.warning("No JSON data provided")
                return jsonify({
                    "error": "No JSON data provided",
                    "valid": False
                }), 400

            # Извлекаем session_id и access_token из JSON
            session_id = data.get('session_id')
            access_token = data.get('access_token')

            if not session_id or not access_token:
                current_app.logger.warning("Missing session_id or access_token in JSON")
                return jsonify({
                    "error": "Missing session_id or access_token in JSON data",
                    "valid": False
                }), 400

            # Проверяем сессию
            if not is_session_valid(session_id, access_token):
                current_app.logger.info(f"Invalid session: {session_id[:10]}...")
                return jsonify({
                    "error": "Invalid or expired session",
                    "valid": False
                }), 401

            # Сохраняем данные сессии в g (контекст фласка для запросов)
            g.session_data = {
                'session_id': session_id,
                'access_token': access_token
            }

            current_app.logger.info(f"Session validated for: {session_id[:10]}...")
            return f(*args, **kwargs)

        except Exception as e:
            current_app.logger.error(f"Error validating session: {e}", exc_info=True)
            return jsonify({
                "error": "Session validation failed",
                "valid": False
            }), 500

    return decorated


@bp.route("/get-service-token", methods=["POST"])
@require_internal_api_key
def get_service_token():
    """
    Получение токена для сервиса.
    """
    try:
        # Получаем данные для создания токена
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        service_name = data.get('service_name')
        description = data.get('description', '')

        if not service_name:
            return jsonify({"error": "service_name is required"}), 400

        # Создаем токен
        from ..utils import create_service_token
        token_info = create_service_token(
            service_name=service_name,
            description=description
        )

        if not token_info:
            return jsonify({"error": "Failed to create service token"}), 500

        current_app.logger.info(f"Service token created for: {service_name}")

        # Возвращаем токен (обратите внимание: токен возвращается только один раз!)
        return jsonify({
            "success": True,
            "token": token_info['token'],
            "service_name": token_info['service_name'],
            "expires_at": token_info['expires_at'],
            "valid_days": token_info['valid_days'],
            "warning": "Save this token securely. It will not be shown again."
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error creating service token: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/validate-session", methods=["POST"])
@require_internal_token
def validate_session():
    """Валидация сессии пользователя"""
    try:
        # Получаем данные из JSON
        data = request.get_json()
        if not data:
            current_app.logger.warning("No JSON data provided")
            return jsonify({
                "valid": False,
                "error": "No JSON data provided"
            }), 400

        # Извлекаем session_id и access_token из JSON
        session_id = data.get('session_id')
        access_token = data.get('access_token')

        if not session_id or not access_token:
            current_app.logger.warning("Missing session_id or access_token in JSON")
            return jsonify({
                "valid": False,
                "error": "Missing session_id or access_token in JSON data"
            }), 400

        # Проверяем сессию
        is_valid = is_session_valid(session_id, access_token)

        current_app.logger.info(f"Session validation for {session_id[:10]}...: {is_valid}")

        return jsonify({
            "valid": is_valid,
            "session_id": session_id
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error validating session: {e}", exc_info=True)
        return jsonify({
            "valid": False,
            "error": str(e)
        }), 500


@bp.route("/get-account-info", methods=["POST"])
@require_internal_token
@require_valid_session
def get_account_info():
    """Получение информации об аккаунте пользователя по текущей сессии"""
    try:
        # Получаем данные сессии из контекста (уже проверено декоратором)
        session_id = g.session_data['session_id']

        # Получаем account_id по session_id
        account_id = get_session_account_id(session_id)

        if not account_id:
            return jsonify({
                "error": "Account not found for session",
                "session_valid": True
            }), 404

        # Находим аккаунт по ID
        from ..models import Account
        account = Account.query.get(account_id)

        if not account:
            return jsonify({
                "error": "Account not found",
                "session_valid": True
            }), 404

        # Формируем информацию об аккаунте
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

        current_app.logger.info(f"Account info retrieved for session: {session_id[:10]}...")

        return jsonify({
            "success": True,
            "account": account_info,
            "session_id": session_id,
            "session_valid": True
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in get_account_info: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "session_valid": True
        }), 500


@bp.route("/get-session-info", methods=["POST"])
@require_internal_token
@require_valid_session
def get_session_info():
    """Получение информации о текущей сессии"""
    try:
        # Получаем данные сессии из контекста
        session_id = g.session_data['session_id']

        # Находим сессию в БД
        session = UserSession.query.filter_by(session_id=session_id).first()

        if not session:
            return jsonify({
                "error": "Session not found in database",
                "session_valid": False
            }), 404

        # Получаем информацию об аккаунте
        account_info = None
        if session.account:
            account_info = {
                'id': session.account.id,
                'username': session.account.username,
                'email': session.account.email,
                'public_id': session.account.public_id,
                'is_verified': session.account.is_verified
            }

        # Формируем информацию о сессии
        session_info = {
            'session_id': session.session_id,
            'account_id': session.account_id,
            'created_at': session.created_at.isoformat() if session.created_at else None,
            'last_used': session.last_used.isoformat() if session.last_used else None,
            'expires_at': session.expires_at.isoformat() if session.expires_at else None,
            'is_active': session.is_active,
            'user_agent': session.user_agent_original,
            'account': account_info
        }

        current_app.logger.info(f"Session info retrieved for: {session_id[:10]}...")

        return jsonify({
            "success": True,
            "session": session_info,
            "session_valid": True
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in get_session_info: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "session_valid": True
        }), 500


@bp.route("/get-all-session-info", methods=["POST"])
@require_internal_token
@require_valid_session
def get_all_session_info():
    """Получение информации о всех активных сессиях пользователя"""
    try:
        # Получаем данные сессии из контекста
        session_id = g.session_data['session_id']

        # Получаем account_id по session_id
        account_id = get_session_account_id(session_id)

        if not account_id:
            return jsonify({
                "error": "Account not found for session",
                "session_valid": True
            }), 404

        # Находим все активные сессии аккаунта
        sessions = UserSession.query.filter_by(
            account_id=account_id,
            is_active=True
        ).order_by(UserSession.created_at.desc()).all()

        # Формируем список информации о сессиях
        sessions_info = []
        for session in sessions:
            session_info = {
                'session_id': session.session_id,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'last_used': session.last_used.isoformat() if session.last_used else None,
                'expires_at': session.expires_at.isoformat() if session.expires_at else None,
                'user_agent': session.user_agent_original,
                'is_current': session.session_id == session_id  # Отмечаем текущую сессию
            }
            sessions_info.append(session_info)

        # Получаем информацию об аккаунте
        from ..models import Account
        account = Account.query.get(account_id)
        account_info = None
        if account:
            account_info = {
                'id': account.id,
                'username': account.username,
                'email': account.email,
                'public_id': account.public_id,
                'total_active_sessions': len(sessions)
            }

        current_app.logger.info(f"All session info retrieved for account: {account_id}")

        return jsonify({
            "success": True,
            "account": account_info,
            "sessions": sessions_info,
            "total_sessions": len(sessions_info),
            "session_valid": True
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error in get_all_session_info: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "session_valid": True
        }), 500


@bp.route("/logout", methods=["POST"])
@require_internal_token
@require_valid_session
def logout():
    """Выход из текущей сессии (удаление сессии из БД)"""
    try:
        # Получаем данные сессии из контекста
        session_id = g.session_data['session_id']

        # Удаляем сессию из БД
        deleted = delete_session_by_id(session_id)

        if deleted:
            current_app.logger.info(f"Session {session_id[:10]}... deleted via internal API")
            return jsonify({
                "success": True,
                "message": "Session terminated successfully",
                "session_id": session_id,
                "deleted": True
            }), 200
        else:
            current_app.logger.warning(f"Session {session_id[:10]}... not found for deletion")
            return jsonify({
                "success": False,
                "message": "Session not found",
                "session_id": session_id,
                "deleted": False,
                "session_valid": True
            }), 404

    except Exception as e:
        current_app.logger.error(f"Error in logout: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "session_valid": True
        }), 500


@bp.route("/logout-all", methods=["POST"])
@require_internal_token
@require_valid_session
def logout_all():
    """Выход из всех сессий пользователя (удаление всех сессий из БД)"""
    try:
        # Получаем данные сессии из контекста
        session_id = g.session_data['session_id']

        # Получаем account_id по session_id
        account_id = get_session_account_id(session_id)

        if not account_id:
            return jsonify({
                "error": "Account not found for session",
                "session_valid": True
            }), 404

        # Удаляем все сессии аккаунта из БД
        deleted = delete_all_sessions_by_account_id(account_id)

        if deleted:
            current_app.logger.info(f"All sessions deleted for account: {account_id} via internal API")
            return jsonify({
                "success": True,
                "message": "All sessions terminated successfully",
                "account_id": account_id,
                "deleted": True
            }), 200
        else:
            current_app.logger.warning(f"No sessions found for account: {account_id}")
            return jsonify({
                "success": False,
                "message": "No sessions found for account",
                "account_id": account_id,
                "deleted": False,
                "session_valid": True
            }), 404

    except Exception as e:
        current_app.logger.error(f"Error in logout-all: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "session_valid": True
        }), 500


@bp.route("/ban", methods=["POST"])
@require_internal_token
@require_valid_session
def ban():
    pass