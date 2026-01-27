from flask import Blueprint
from ..limiter import limiter


bp = Blueprint('public', __name__)


@bp.route("/registration", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def registration():
    pass


@bp.route("/login", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def login():
    pass


@bp.route("/verify", methods=["POST"])
@limiter.limit("5 per 2 minutes, 20 per hour, 3 per minute")
def verify():
    pass


@bp.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per 5 minutes, 10 per hour, 2 per 2 minutes")
def resend_verification():
    pass


@bp.route("/account", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def account():
    pass


@bp.route("/logout", methods=["POST"])
@limiter.limit("20 per minute, 50 per hour")
def logout():
    pass


@bp.route("/reset", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def logout():
    pass


@bp.route("/logout-all", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def logout_all():
    pass


@bp.route("/delete", methods=["POST"])
@limiter.limit("5 per minute, 10 per hour")
def delete():
    pass


@bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute, 30 per hour")
def reset():
    pass


@bp.route('/health')
@limiter.limit("30 per minute, 180 per hour")
def health():
    return "OK", 200