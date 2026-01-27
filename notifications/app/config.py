import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # SMTP
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT'))
    SMTP_LOGIN = os.environ.get('SMTP_LOGIN')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    SENDER_NAME = os.environ.get('SENDER_NAME')

    # Redis
    NOTIFICATION_QUEUE_REDIS_URL = os.environ.get('NOTIFICATION_QUEUE_REDIS_URL')

    # Очередь
    RQ_QUEUE_NAME = os.environ.get('RQ_QUEUE_NAME')
    RQ_RETRY_MAX = int(os.environ.get('RQ_RETRY_MAX'))
    RQ_RETRY_INTERVAL = int(os.environ.get('RQ_RETRY_INTERVAL'))

    # Пароль API
    INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY')