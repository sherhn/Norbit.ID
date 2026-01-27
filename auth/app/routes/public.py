import re
from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, current_app, jsonify
from ..limiter import limiter
from ..models import db, Account, UserSession


bp = Blueprint('public', __name__)

# Проверки никнейма и почты
USERNAME_REGEX = re.compile(r'^[\w-]{3,12}$', re.UNICODE)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


@bp.route("/registration", methods=["POST"])
@limiter.limit("30 per minute, 100 per hour, 5 per 30 seconds")
def registration():

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

        if len(password) < 8:
            return jsonify({"message": "Short Password"}, 400)

        # TODO: Сделать проверку надежности пароля

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
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration commit failed: {e}", exc_info=True)
            return jsonify({"message": "Registration Failed"}), 500

        # TODO: Отправка кода подтверждения

        return jsonify({"message": "Registration Success"}), 201

    except Exception as e:
        current_app.logger.error(f"Unexpected error in register: {e}", exc_info=True)
        return jsonify({"message": "Internal Error"}), 500

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
def reset():
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
def refresh():
    pass


@bp.route('/health')
@limiter.limit("30 per minute, 180 per hour")
def health():
    return "OK", 200