from rq import Queue
from app import create_app
from app.logging_config import setup_logging
import logging


if __name__ == '__main__':
    # Настройка логирования
    setup_logging(container_name="notifications_worker")

    logger = logging.getLogger(__name__)
    logger.info("Starting RQ worker...")

    # Flask-приложение, которое инициализирует redis_conn
    app = create_app()

    # Запускаем воркера в контексте приложения
    with app.app_context():
        from app import redis_conn

        # Создаем очередь, используя инициализированное соединение
        q = Queue(app.config['RQ_QUEUE_NAME'], connection=redis_conn)

        # Запускаем воркера
        from rq.worker import Worker

        worker = Worker([q], connection=redis_conn)
        logger.info(f"Worker started, listening to queue: {app.config['RQ_QUEUE_NAME']}")
        worker.work()