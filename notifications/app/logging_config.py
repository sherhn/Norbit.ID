import logging
import sys
import json
from flask import has_request_context, request

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "service": "notifications",
            "container": "notifications_service",
        }

        # Полный traceback для ошибок
        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)

def setup_logging(container_name="notifications_service"):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    # Root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)  # ERROR в проде, но пока хай будет инфо

    # Flask logger
    app_logger = logging.getLogger('flask.app')
    app_logger.handlers.clear()
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.INFO)

    # RQ logger
    rq_logger = logging.getLogger('rq.worker')
    rq_logger.handlers.clear()
    rq_logger.addHandler(handler)
    rq_logger.setLevel(logging.INFO)

    # Убираем дублирующий вывод
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    # Устанавливаем переменную окружения для RQ
    import os
    os.environ['RQ_WORKER_LOG_FORMAT'] = ''  # Отключаем дефолтный формат RQ

    print(f"JSON logging initialized for {container_name}", file=sys.stderr)