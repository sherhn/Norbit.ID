from flask import Blueprint, request, jsonify, current_app
from rq import Queue
from app import redis_conn
from app.tasks import send_verification_email
from app.config import Config
from functools import wraps

bp = Blueprint('notifications', __name__)


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


@bp.route('/send-verification', methods=['POST'])
@require_internal_key
def send_verification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    email = data.get('email')
    code = data.get('code')
    operation = data.get('operation')

    if not all([email, code, operation]):
        return jsonify({"error": "Missing required fields"}), 400

    if len(str(code)) != 6 or not str(code).isdigit():
        return jsonify({"error": "Code must be 6 digits"}), 400

    q = Queue(Config.RQ_QUEUE_NAME, connection=redis_conn)
    job = q.enqueue(
        send_verification_email,
        email, code, operation,
        retries=Config.RQ_RETRY_MAX,
        retry_intervals=Config.RQ_RETRY_INTERVAL
    )

    return jsonify({
        "status": "queued",
        "job_id": job.id,
        "email": email
    }), 202


@bp.route('/health', methods=['GET'])
def health():
    return "OK", 200