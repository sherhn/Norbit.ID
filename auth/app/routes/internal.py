from functools import wraps
from flask import Blueprint, request, current_app, jsonify
from ..utils import get_account_by_public_id

bp = Blueprint('internal', __name__)


def require_internal_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = (
            request.headers.get('X-API-Key') or
            (request.get_json(silent=True) or {}).get('api_key')
        )
        expected_key = current_app.config['INTERNAL_API_KEY']
        if not provided_key or provided_key != expected_key:
            current_app.logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@bp.route("/validate-session", methods=["POST"])
@require_internal_key
def validate_session():
    pass


@bp.route("/get-account-info", methods=["POST"])
@require_internal_key
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
                "account": account_info
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Account not found"
            }), 404

    except ValueError as e:
        # Ловим ошибку, если не переданы оба параметра
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error in get_account_info: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/get-session-info", methods=["POST"])
@require_internal_key
def get_session_info():
    pass


@bp.route("/logout", methods=["POST"])
def logout():
    pass


@bp.route("/logout-all", methods=["POST"])
def logout_all():
    pass


@bp.route("/refresh", methods=["POST"])
def refresh():
    pass