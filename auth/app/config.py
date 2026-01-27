import os
import json
from datetime import timedelta


class Config:
    # Внутр. апи ключ
    INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('AUTH_DATABASE_URL')

    # Коды подтверждения
    REDIS_CODES_URL = os.environ.get('REDIS_CODES_URL')