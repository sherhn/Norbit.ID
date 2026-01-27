from functools import wraps
from flask import Blueprint, request, current_app, jsonify

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
    pass


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