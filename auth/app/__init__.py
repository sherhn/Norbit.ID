import logging
from flask import Flask
from sqlalchemy import text
from .config import Config
from .models import db
from .limiter import limiter
from .logging_config import setup_logging


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # Стартуем логи
    setup_logging()

    logger = logging.getLogger(__name__)
    logger.info("Flask application created")

    # Инициализация расширений
    db.init_app(app)
    limiter.init_app(app)

    # Создание таблиц в контексте приложения
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created/verified")

            # Включение аудита для таблиц в БД
            try:
                # Проверяем что таблицы существуют перед установкой триггеров
                result = db.session.execute(text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name IN ('accounts', 'verification_codes', 'user_sessions')
                """))
                existing_tables = [row[0] for row in result]

                app.logger.info(f"Found tables: {existing_tables}")

                if 'accounts' in existing_tables:
                    db.session.execute(text("SELECT enable_table_audit('accounts')"))
                    app.logger.info("Audit enabled for accounts table")

                if 'verification_codes' in existing_tables:
                    db.session.execute(text("SELECT enable_table_audit('verification_codes')"))
                    app.logger.info("Audit enabled for verification_codes table")

                if 'user_sessions' in existing_tables:
                    db.session.execute(text("SELECT enable_table_audit('user_sessions')"))
                    app.logger.info("Audit enabled for user_sessions table")

                db.session.commit()
                app.logger.info("Database audit triggers enabled successfully")

                # Проверим что триггеры установились
                triggers_result = db.session.execute(text("""
                    SELECT tgname as trigger_name, relname as table_name
                    FROM pg_trigger tg
                    JOIN pg_class cls ON cls.oid = tg.tgrelid
                    WHERE tgname LIKE 'audit_trigger%'
                """))
                triggers = [f"{row[0]} on {row[1]}" for row in triggers_result]
                app.logger.info(f"Active audit triggers: {triggers}")

            except Exception as audit_error:
                db.session.rollback()
                app.logger.error(f"Failed to enable audit triggers: {audit_error}", exc_info=True)

        except Exception as e:
            app.logger.warning(f"Tables already exist or error: {e}", exc_info=True)

    # Регистрация blueprint'ов
    from .routes.public import bp as public_bp
    from .routes.internal import bp as internal_bp

    app.register_blueprint(public_bp, url_prefix='/api/auth')
    app.register_blueprint(internal_bp, url_prefix='/internal/auth')

    logger.info("Blueprints registered successfully")

    return app
