# Документация модуля utils.py

## Общее описание
Модуль `utils.py` содержит вспомогательные функции для работы с аутентификацией, сессиями, токенами, Redis, кодами подтверждения и другими вспомогательными операциями.

---

## Функции

### `generate_service_token(length: int = 64) -> str`
**Назначение:** Генерация токена для сервисов.

**Аргументы:**
- `length` (int, по умолчанию 64) - длина генерируемого токена.

**Возвращает:**
- `str` - случайно сгенерированный токен, состоящий из букв и цифр.

**Требования:**
- Длина должна быть положительным числом.

---

### `hash_service_token(token: str) -> str`
**Назначение:** Хеширование токена сервиса для безопасного хранения.

**Аргументы:**
- `token` (str) - исходный токен для хеширования.

**Возвращает:**
- `str` - hex-строка хеша SHA256.

**Требования:**
- Токен должен быть непустой строкой.

---

### `create_service_token(service_name: str, description: str = None) -> Optional[Dict[str, Any]]`
**Назначение:** Создание и сохранение токена для сервиса в БД.

**Аргументы:**
- `service_name` (str) - название сервиса.
- `description` (str, опционально) - описание токена.

**Возвращает:**
- `Optional[Dict[str, Any]]` - словарь с информацией о токене или `None` при ошибке.
- Структура ответа:
  ```json
  {
    "token": "сгенерированный_токен",
    "service_name": "название_сервиса",
    "created_at": "дата_создания",
    "expires_at": "дата_истечения",
    "valid_hours": 1
  }
  ```

**Требования:**
- `service_name` обязателен и не должен быть пустым.
- Требуется контекст Flask приложения.

---

### `validate_service_token(token: str) -> Optional[Dict[str, Any]]`
**Назначение:** Проверка валидности токена сервиса.

**Аргументы:**
- `token` (str) - токен для проверки.

**Возвращает:**
- `Optional[Dict[str, Any]]` - информация о токене или `None` если токен невалиден.
- Структура ответа:
  ```json
  {
    "id": 123,
    "service_name": "название_сервиса",
    "description": "описание",
    "created_at": "дата_создания",
    "expires_at": "дата_истечения",
    "last_used": "последнее_использование"
  }
  ```

**Требования:**
- Токен должен быть строкой.
- Автоматически удаляет просроченные токены.

---

### `validate_password_strength(password: str) -> tuple[bool, str]`
**Назначение:** Проверка надежности пароля.

**Аргументы:**
- `password` (str) - пароль для проверки.

**Возвращает:**
- `tuple[bool, str]` - (валиден ли пароль, сообщение об ошибке/успехе).

**Требования к паролю:**
- Минимум 8 символов
- Хотя бы одна цифра
- Хотя бы одна заглавная буква
- Хотя бы одна строчная буква
- (Рекомендуется) хотя бы один специальный символ

---

### `get_redis_client(redis_type: str = 'codes')`
**Назначение:** Инициализация и получение Redis клиента.

**Аргументы:**
- `redis_type` (str) - тип Redis: 'codes' для кодов подтверждения, 'csrf' для CSRF токенов.

**Возвращает:**
- `redis.Redis` - объект Redis клиента.

**Требования:**
- Конфигурационные переменные `REDIS_CODES_URL` и `REDIS_CSRF_URL` должны быть установлены.
- Использует пул соединений.

---

### `generate_verification_code(length: int = 6) -> str`
**Назначение:** Генерация случайного цифрового кода подтверждения.

**Аргументы:**
- `length` (int, по умолчанию 6) - длина кода.

**Возвращает:**
- `str` - строку с цифровым кодом.

---

### `hash_verification_code(code: str) -> Tuple[bytes, bytes]`
**Назначение:** Хеширование кода подтверждения с солью.

**Аргументы:**
- `code` (str) - код для хеширования.

**Возвращает:**
- `Tuple[bytes, bytes]` - (хешированный код, соль).

---

### `verify_code_hash(code: str, hashed_code: bytes, salt: bytes) -> bool`
**Назначение:** Проверка кода подтверждения.

**Аргументы:**
- `code` (str) - введенный код
- `hashed_code` (bytes) - хранимый хеш
- `salt` (bytes) - соль

**Возвращает:**
- `bool` - `True` если код верный, иначе `False`.

---

### `create_verification_code(user_id: int, operation: str, ttl_minutes: int = 10) -> Optional[str]`
**Назначение:** Создание и сохранение кода подтверждения в Redis.

**Аргументы:**
- `user_id` (int) - ID пользователя
- `operation` (str) - тип операции ('register', 'reset_password', 'login', 'delete')
- `ttl_minutes` (int, по умолчанию 10) - время жизни кода в минутах

**Возвращает:**
- `Optional[str]` - сгенерированный код или `None` при ошибке.

**Особенности:**
- Автоматически удаляет старые коды для пользователя.
- Хранит хеш кода, а не сам код.

---

### `verify_verification_code(user_id: int, code: str, operation: str, increment_failed: bool = True) -> bool`
**Назначение:** Проверка кода подтверждения.

**Аргументы:**
- `user_id` (int) - ID пользователя
- `code` (str) - введенный код
- `operation` (str) - тип операции
- `increment_failed` (bool) - увеличивать счетчик неудачных попыток

**Возвращает:**
- `bool` - `True` если код верный, иначе `False`.

**Особенности:**
- Блокирует код после 5 неудачных попыток.

---

### `delete_verification_code(user_id: int, operation: str) -> bool`
**Назначение:** Удаление кода подтверждения из Redis.

**Аргументы:**
- `user_id` (int) - ID пользователя
- `operation` (str) - тип операции

**Возвращает:**
- `bool` - `True` если удалено, иначе `False`.

---

### `send_verification_email(email: str, code: str, operation: str) -> bool`
**Назначение:** Отправка кода подтверждения на email через внутренний сервис.

**Аргументы:**
- `email` (str) - email получателя
- `code` (str) - код подтверждения
- `operation` (str) - тип операции

**Возвращает:**
- `bool` - `True` если успешно, `False` при ошибке.

**Требования:**
- Требуется настройка `INTERNAL_NOTIFICATION_SERVICE_URL` и `INTERNAL_API_KEY`.

---

### `create_jwt_tokens(account_id: int, public_id: str, session_id: str = None) -> Dict[str, str]`
**Назначение:** Создание JWT токенов (access и refresh).

**Аргументы:**
- `account_id` (int) - ID аккаунта в БД
- `public_id` (str) - публичный ID аккаунта
- `session_id` (str) - ID сессии (обязателен!)

**Возвращает:**
- `Dict[str, str]` - словарь с токенами:
  ```json
  {
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token"
  }
  ```

**Требования:**
- `session_id` обязателен.

---

### `verify_jwt_token(token: str, token_type: str = 'access', expected_session_id: str = None) -> Optional[Dict]`
**Назначение:** Верификация JWT токена.

**Аргументы:**
- `token` (str) - JWT токен
- `token_type` (str) - тип токена ('access' или 'refresh')
- `expected_session_id` (str, опционально) - ожидаемый session_id для дополнительной проверки

**Возвращает:**
- `Optional[Dict]` - распарсенный payload или `None` если токен невалидный.

---

### `hash_string(data: str) -> str`
**Назначение:** Хеширование строки с использованием SHA256.

**Аргументы:**
- `data` (str) - строка для хеширования

**Возвращает:**
- `str` - hex-строка хеша SHA256.

---

### `create_user_session(account_id: int, refresh_token: str, user_agent: str) -> Optional[Dict[str, Any]]`
**Назначение:** Создание сессии пользователя в БД.

**Аргументы:**
- `account_id` (int) - ID аккаунта
- `refresh_token` (str) - refresh токен
- `user_agent` (str) - User-Agent браузера

**Возвращает:**
- `Optional[Dict[str, Any]]` - информация о созданной сессии:
  ```json
  {
    "session_id": "уникальный_id_сессии",
    "created_at": "дата_создания",
    "expires_at": "дата_истечения"
  }
  ```

**Особенности:**
- Автоматически удаляет старые сессии при превышении лимита `MAX_SESSIONS_PER_USER`.

---

### `set_session_cookie(response, session_id: str, access_token: str)`
**Назначение:** Установка сессионной куки.

**Аргументы:**
- `response` - Flask response object
- `session_id` (str) - ID сессии
- `access_token` (str) - access токен

**Особенности:**
- Кука содержит `session_id:access_token`.
- Настройки куки берутся из конфигурации.

---

### `get_session_from_cookie(request) -> Optional[Dict[str, str]]`
**Назначение:** Извлечение сессии из куки.

**Аргументы:**
- `request` - Flask request object

**Возвращает:**
- `Optional[Dict[str, str]]` - словарь с session_id и access_token или `None`:
  ```json
  {
    "session_id": "id_сессии",
    "access_token": "access_токен"
  }
  ```

---

### `is_session_valid(session_id: str, access_token: str) -> bool`
**Назначение:** Проверка валидности сессии.

**Аргументы:**
- `session_id` (str) - ID сессии
- `access_token` (str) - access токен

**Возвращает:**
- `bool` - `True` если сессия валидна, иначе `False`.

**Логика проверки:**
1. Проверяет существование сессии в БД
2. Проверяет срок действия сессии
3. Верифицирует access токен
4. Проверяет соответствие account_id
5. Обновляет время последнего использования

---

### `delete_session_by_id(session_id: str) -> bool`
**Назначение:** Полное удаление сессии из БД по ID.

**Аргументы:**
- `session_id` (str) - ID сессии для удаления

**Возвращает:**
- `bool` - `True` если удалено, иначе `False`.

---

### `delete_all_sessions_by_account_id(account_id: int) -> bool`
**Назначение:** Полное удаление всех сессий аккаунта из БД.

**Аргументы:**
- `account_id` (int) - ID аккаунта

**Возвращает:**
- `bool` - `True` если удалено, иначе `False`.

---

### `get_session_account_id(session_id: str) -> Optional[int]`
**Назначение:** Получение ID аккаунта по session_id.

**Аргументы:**
- `session_id` (str) - ID сессии

**Возвращает:**
- `Optional[int]` - ID аккаунта или `None` если сессия не найдена.

---

### `clear_session_cookie(response)`
**Назначение:** Очистка сессионной куки.

**Аргументы:**
- `response` - Flask response object

---

### `delete_account_from_db(account_id: int) -> bool`
**Назначение:** Полное удаление аккаунта из БД.

**Аргументы:**
- `account_id` (int) - ID аккаунта для удаления

**Возвращает:**
- `bool` - `True` если удалено, иначе `False`.

**Особенности:**
- Удаляет все связанные сессии аккаунта.

---

### `issue_session_for_account(account: Account, user_agent: str = "") -> Optional[Dict[str, Any]]`
**Назначение:** Выдача сессии для аккаунта.

**Аргументы:**
- `account` (Account) - объект аккаунта
- `user_agent` (str) - User-Agent браузера

**Возвращает:**
- `Optional[Dict[str, Any]]` - данные сессии:
  ```json
  {
    "session_info": {...},
    "tokens": {...},
    "account": {...}
  }
  ```

---

### `confirm_registration(account_id: int) -> Optional[Account]`
**Назначение:** Подтверждение регистрации (установка `is_verified = True`).

**Аргументы:**
- `account_id` (int) - ID аккаунта

**Возвращает:**
- `Optional[Account]` - обновленный объект аккаунта или `None` при ошибке.

---

### `change_account_password(account_id: int, new_password: str) -> bool`
**Назначение:** Изменение пароля аккаунта.

**Аргументы:**
- `account_id` (int) - ID аккаунта
- `new_password` (str) - новый пароль

**Возвращает:**
- `bool` - `True` если успешно, иначе `False`.

**Особенности:**
- Проверяет надежность нового пароля.
- Сбрасывает счетчик неудачных попыток входа.

---

### `verify_code_for_operation(account_id: int, code: str, operation: str) -> bool`
**Назначение:** Проверка кода подтверждения для конкретной операции.

**Аргументы:**
- `account_id` (int) - ID аккаунта
- `code` (str) - введенный код
- `operation` (str) - тип операции

**Возвращает:**
- `bool` - `True` если код верный, иначе `False`.

---

### `handle_2fa_verification(account: Account, enable_2fa: bool = False) -> Dict[str, Any]`
**Назначение:** Обработка 2FA верификации.

**Аргументы:**
- `account` (Account) - объект аккаунта
- `enable_2fa` (bool) - если `True` - включить 2FA, если `False` - проверить 2FA

**Возвращает:**
- `Dict[str, Any]` - результат операции:
  ```json
  {
    "success": true/false,
    "requires_session": true/false,
    "session_data": {...},
    "message": "сообщение"
  }
  ```

---

### `generate_csrf_token() -> str`
**Назначение:** Генерация CSRF токена.

**Возвращает:**
- `str` - случайно сгенерированный CSRF токен.

---

### `create_csrf_token(session_id: str) -> str`
**Назначение:** Создание и сохранение CSRF токена для сессии в Redis.

**Аргументы:**
- `session_id` (str) - ID сессии пользователя

**Возвращает:**
- `str` - CSRF токен.

**Особенности:**
- Сохраняет хеш токена, а не сам токен.

---

### `validate_csrf_token(session_id: str, csrf_token: str, refresh_ttl: bool = True) -> bool`
**Назначение:** Проверка CSRF токена.

**Аргументы:**
- `session_id` (str) - ID сессии пользователя
- `csrf_token` (str) - CSRF токен для проверки
- `refresh_ttl` (bool) - обновлять ли TTL токена при успешной проверке

**Возвращает:**
- `bool` - `True` если токен валиден, иначе `False`.

---

### `delete_csrf_token(session_id: str) -> bool`
**Назначение:** Удаление CSRF токена из Redis.

**Аргументы:**
- `session_id` (str) - ID сессии

**Возвращает:**
- `bool` - `True` если удалено, иначе `False`.

---

### `get_csrf_token_for_session(session_id: str) -> Optional[str]`
**Назначение:** Получение информации о CSRF токене для сессии.

**Аргументы:**
- `session_id` (str) - ID сессии

**Возвращает:**
- `Optional[str]` - `"[exists]"` если токен существует, иначе `None`.

**Примечание:**
- Не возвращает сам токен из соображений безопасности.

---

## Глобальные переменные

### `redis_codes_client`
- **Тип:** `redis.Redis`
- **Назначение:** Redis клиент для работы с кодами подтверждения.

### `redis_csrf_client`
- **Тип:** `redis.Redis`
- **Назначение:** Redis клиент для работы с CSRF токенами.

### `logger`
- **Тип:** `logging.Logger`
- **Назначение:** Логгер для модуля utils.

---

## Зависимости

- `flask` - для работы с контекстом приложения
- `redis` - для работы с Redis
- `bcrypt` - для хеширования паролей и кодов
- `jwt` - для работы с JWT токенами
- `requests` - для отправки HTTP запросов
- `pyotp` - для работы с двухфакторной аутентификацией
- `hashlib` - для хеширования строк

---

## Обработка ошибок

Большинство функций используют try-except блоки для обработки исключений:
- Возвращают `None` или `False` при ошибках
- Логируют ошибки в журнал
- Выполняют откат транзакций БД при необходимости