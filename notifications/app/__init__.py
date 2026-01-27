from flask import Flask
from redis import Redis
from rq import Queue
from .config import Config
from .logging_config import setup_logging
import logging

redis_conn = None
q = None


def create_app():
    global redis_conn, q
    app = Flask(__name__)
    app.config.from_object(Config)

    # Логи
    setup_logging(container_name="notifications_service")

    logger = logging.getLogger(__name__)
    logger.info("Flask application created")

    # Redis
    redis_conn = Redis.from_url(app.config['NOTIFICATION_QUEUE_REDIS_URL'])
    q = Queue(Config.RQ_QUEUE_NAME, connection=redis_conn)

    logger.info("Redis and RQ queue initialized")

    # Бп
    from .routes.internal import bp
    app.register_blueprint(bp)

    return app