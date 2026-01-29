import os


class Config:
    # Внутр. апи ключ
    INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('AUTH_DATABASE_URL')
    INTERNAL_NOTIFICATION_SERVICE_URL = os.environ.get('INTERNAL_NOTIFICATION_SERVICE_URL')

    # Коды подтверждения
    REDIS_CODES_URL = os.environ.get('REDIS_CODES_URL')

    # CSRF токены (новая база Redis)
    REDIS_CSRF_URL = os.environ.get('REDIS_CSRF_URL')

    # JWT настройки
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 900))  # 15 минут
    JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000))  # 30 дней

    # Срок жизни сервисного токена - 1 час (по дефолту, менять в env)
    SERVICE_TOKEN_EXPIRES_HOURS = int(os.environ.get('SERVICE_TOKEN_EXPIRES_HOURS', 1))

    # Настройки сессий
    MAX_SESSIONS_PER_USER = int(os.environ.get('MAX_SESSIONS_PER_USER', 10))
    SESSION_COOKIE_NAME = 'norbit.id'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
    SESSION_COOKIE_SAMESITE = 'Lax'  # Для кросс-доменных запросов
    SESSION_COOKIE_DOMAIN = os.environ.get('SESSION_COOKIE_DOMAIN', None)  # Для кросс-доменных сессий

    # CSRF настройки
    CSRF_TOKEN_NAME = 'X-CSRF-Token'  # Имя заголовка для CSRF токена
    CSRF_TOKEN_EXPIRES = int(os.environ.get('CSRF_TOKEN_EXPIRES', 1800))  # 30 минут
    CSRF_TOKEN_LENGTH = int(os.environ.get('CSRF_TOKEN_LENGTH', 32))  # Длина токена
    CSRF_REFRESH_ON_USE = os.environ.get('CSRF_REFRESH_ON_USE',
                                         'True').lower() == 'true'  # Обновлять ли TTL при использовании