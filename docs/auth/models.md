## PostgreSQL - Основная база данных

База данных для хранения информации о пользователях, сессиях и сервисных токенах.

### Таблица `accounts`

Основная таблица пользователей.

| Поле | Тип | Описание |
|------|-----|----------|
| `id` | Integer, PRIMARY KEY | Уникальный идентификатор аккаунта |
| `username` | String(20), NOT NULL, INDEX | Имя пользователя (3-12 символов, буквы, цифры, дефис, подчеркивание) |
| `email` | String(255), UNIQUE, NOT NULL, INDEX | Электронная почта пользователя |
| `password_hash` | String(128), NOT NULL | Хеш пароля (bcrypt) |
| `is_verified` | Boolean, DEFAULT False, NOT NULL | Флаг подтверждения email |
| `created_at` | DateTime, DEFAULT now(), INDEX | Дата и время создания аккаунта |
| `public_id` | String(16), UNIQUE, NOT NULL, INDEX | Публичный идентификатор аккаунта (для внешнего использования) |
| `two_factor_enabled` | Boolean, DEFAULT False, NOT NULL | Флаг включения двухфакторной аутентификации |
| `two_factor_secret` | String(32), NULLABLE | Секрет для 2FA (TOTP) |
| `failed_login_attempts` | Integer, DEFAULT 0, NOT NULL | Количество неудачных попыток входа |
| `locked_until` | DateTime, NULLABLE, INDEX | Время до разблокировки аккаунта |
| `last_failed_login` | DateTime, NULLABLE | Время последней неудачной попытки входа |

**Связи:**
- Имеет множество сессий (`user_sessions`)

### Таблица `user_sessions`

Таблица для хранения активных сессий пользователей.

| Поле | Тип | Описание |
|------|-----|----------|
| `id` | Integer, PRIMARY KEY | Уникальный идентификатор сессии |
| `account_id` | Integer, FOREIGN KEY, NOT NULL, INDEX | Ссылка на аккаунт (accounts.id) |
| `session_id` | String(64), UNIQUE, NOT NULL, INDEX | Уникальный идентификатор сессии (используется в куках) |
| `refresh_token_hash` | String(128), NOT NULL | Хеш refresh токена (SHA256) |
| `user_agent_hash` | String(128), NOT NULL | Хеш User-Agent браузера |
| `created_at` | DateTime, DEFAULT now(), NOT NULL, INDEX | Дата и время создания сессии |
| `last_used` | DateTime, DEFAULT now(), NOT NULL, INDEX | Дата и время последнего использования |
| `expires_at` | DateTime, NOT NULL, INDEX | Дата и время истечения срока действия |
| `is_active` | Boolean, DEFAULT True, NOT NULL | Флаг активности сессии |
| `user_agent_original` | Text, NULLABLE | Оригинальный User-Agent (до 500 символов) |

**Связи:**
- Принадлежит одному аккаунту (`accounts.id`)

### Таблица `service_tokens`

Таблица для хранения токенов внутренних сервисов.

| Поле | Тип | Описание |
|------|-----|----------|
| `id` | Integer, PRIMARY KEY | Уникальный идентификатор токена |
| `service_name` | String(100), NOT NULL, INDEX | Название сервиса |
| `token_hash` | String(128), NOT NULL, INDEX | Хеш токена сервиса (SHA256) |
| `description` | Text, NULLABLE | Описание токена |
| `created_at` | DateTime, DEFAULT now(), NOT NULL | Дата и время создания |
| `expires_at` | DateTime, NOT NULL, INDEX | Дата и время истечения срока действия |
| `last_used` | DateTime, NULLABLE | Дата и время последнего использования |
| `is_active` | Boolean, DEFAULT True, NOT NULL | Флаг активности токена |

## Redis - Временное хранилище

Используется два экземпляра Redis для разных целей.

### Redis для кодов подтверждения (REDIS_CODES_URL)

**Назначение:** Хранение кодов подтверждения для различных операций.

**Структура ключей:**
```
verification_code:{user_id}:{operation}
```

**Типы операций:**
- `registration` - подтверждение регистрации
- `login` - двухфакторная аутентификация
- `reset` - сброс пароля
- `delete` - удаление аккаунта

**Структура данных:**
```json
{
  "hashed_code": "хеш_кода",
  "salt": "соль",
  "created_at": "ISO_дата",
  "failed_attempts": 0,
  "used": false
}
```

**TTL:** 10 минут для кодов, 1 час для аудита использованных кодов.

### Redis для CSRF токенов (REDIS_CSRF_URL)

**Назначение:** Хранение CSRF токенов для защиты от межсайтовой подделки запросов.

**Структура ключей:**
```
csrf_token:{session_id}
```

**Значение:** Хеш CSRF токена (SHA256)

**TTL:** 30 минут по умолчанию, обновляется при использовании (опционально).

## Связи между таблицами

```
accounts (1) ── (много) user_sessions
```

- Один аккаунт может иметь множество активных сессий
- Каждая сессия принадлежит ровно одному аккаунту
- При удалении аккаунта удаляются все его сессии (каскадное удаление через код приложения)

## Аудит

В базе данных PostgreSQL настроены триггеры аудита для отслеживания изменений:
- `accounts` - аудит изменений аккаунтов
- `user_sessions` - аудит изменений сессий
- `service_tokens` - аудит изменений сервисных токенов

Аудит включается автоматически при создании таблиц через функцию `enable_table_audit()`.