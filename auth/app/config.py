import os
import json
from datetime import timedelta


class Config:
    # Внутр. апи ключ
    INTERNAL_API_KEY = os.environ.get('INTERNAL_API_KEY')