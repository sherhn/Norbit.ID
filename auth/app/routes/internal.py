from functools import wraps
from flask import Blueprint, request, current_app, jsonify, g
from ..utils import get_account_by_public_id, is_session_valid, validate_service_token

bp = Blueprint('internal', __name__)


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
def get_service_token():
    """
    Получение токена для сервиса.\
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
            description=description,
            valid_days=180
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
            "warning": "Save this token securely. It will not be shown again."
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error creating service token: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/validate-session", methods=["GET"])
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
            "session_id": session_id if len(session_id) < 20 else session_id[:20] + '...'
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
    """Получение информации об аккаунте по public_id или email"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        public_id = data.get('public_id')
        email = data.get('email')

        # Поиск
        account_info = get_account_by_public_id(public_id=public_id, email=email)

        if account_info:
            return jsonify({
                "success": True,
                "account": account_info,
                "session_valid": True
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Account not found",
                "session_valid": True
            }), 404

    except ValueError as e:
        # Ловим ошибку, если не переданы оба параметра
        return jsonify({"error": str(e), "session_valid": True}), 400
    except Exception as e:
        current_app.logger.error(f"Error in get_account_info: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "session_valid": True}), 500


@bp.route("/get-session-info", methods=["POST"])
@require_internal_token
@require_valid_session
def get_session_info():
    pass


@bp.route("/logout", methods=["POST"])
@require_internal_token
@require_valid_session
def logout():
    pass


@bp.route("/logout-all", methods=["POST"])
@require_internal_token
@require_valid_session
def logout_all():
    pass


@bp.route("/refresh", methods=["POST"])
@require_internal_token
def refresh():
    pass