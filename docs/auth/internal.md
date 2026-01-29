# Документация API аутентификации (Internal Endpoints)

## Общая информация

Internal endpoints предназначены для взаимодействия между внутренними сервисами компании (микросервисами). Все эндпоинты доступны по префиксу `/internal/auth`. Эти эндпоинты предоставляют сервисам возможность управлять пользовательскими сессиями и получать информацию о пользователях.

---

## Авторизация для сервисов

### Получение токена сервиса

**Endpoint:** `POST /internal/auth/get-service-token`

**Требования:**
- Внутренний API ключ в заголовке `X-API-Key`
- JSON в теле запроса

**Входные данные:**
```json
{
  "service_name": "название_сервиса",
  "description": "описание токена (опционально)"
}
```

**Описание:**
Создает токен для внутреннего сервиса. Токен действует 1 час (настраивается). **Важно:** токен возвращается только один раз при создании!

**Response (200 OK):**
```json
{
  "success": true,
  "token": "сгенерированный_токен",
  "service_name": "название_сервиса",
  "expires_at": "2024-01-15T12:00:00",
  "valid_hours": 1,
  "warning": "Save this token securely. It will not be shown again."
}
```

---

## Управление пользовательскими сессиями

### Валидация сессии пользователя

**Endpoint:** `POST /internal/auth/validate-session`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса

**Входные данные:**
```json
{
  "session_id": "идентификатор_сессии",
  "access_token": "access_токен_пользователя"
}
```

**Описание:**
Проверяет валидность пользовательской сессии. Используется сервисами для проверки, действительна ли сессия пользователя.

**Response (200 OK):**
```json
{
  "valid": true,
  "session_id": "идентификатор_сессии"
}
```

---

### Получение информации о пользователе

**Endpoint:** `POST /internal/auth/get-account-info`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса с сессией пользователя
- Декоратор `@require_valid_session`

**Входные данные:**
```json
{
  "session_id": "идентификатор_сессии",
  "access_token": "access_токен_пользователя"
}
```

**Описание:**
Возвращает информацию об аккаунте пользователя по его текущей сессии. Используется сервисами для получения данных пользователя.

**Response (200 OK):**
```json
{
  "success": true,
  "account": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "is_verified": true,
    "created_at": "2024-01-10T10:30:00",
    "public_id": "abc123def456",
    "two_factor_enabled": false,
    "failed_login_attempts": 0,
    "locked_until": null,
    "last_failed_login": null
  },
  "session_id": "идентификатор_сессии",
  "session_valid": true
}
```

---

### Получение информации о текущей сессии

**Endpoint:** `POST /internal/auth/get-session-info`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса с сессией пользователя
- Декоратор `@require_valid_session`

**Описание:**
Возвращает детальную информацию о текущей сессии пользователя, включая user agent и информацию об аккаунте.

**Response (200 OK):**
```json
{
  "success": true,
  "session": {
    "session_id": "идентификатор_сессии",
    "account_id": 123,
    "created_at": "2024-01-15T10:00:00",
    "last_used": "2024-01-15T11:30:00",
    "expires_at": "2024-02-14T10:00:00",
    "is_active": true,
    "user_agent": "Mozilla/5.0...",
    "account": {
      "id": 123,
      "username": "john_doe",
      "email": "john@example.com",
      "public_id": "abc123def456",
      "is_verified": true
    }
  },
  "session_valid": true
}
```

---

### Получение информации о всех сессиях пользователя

**Endpoint:** `POST /internal/auth/get-all-session-info`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса с сессией пользователя
- Декоратор `@require_valid_session`

**Описание:**
Возвращает информацию о всех активных сессиях пользователя. Полезно для административных панелей или сервисов безопасности.

**Response (200 OK):**
```json
{
  "success": true,
  "account": {
    "id": 123,
    "username": "john_doe",
    "email": "john@example.com",
    "public_id": "abc123def456",
    "total_active_sessions": 3
  },
  "sessions": [
    {
      "session_id": "session_1",
      "created_at": "2024-01-15T10:00:00",
      "last_used": "2024-01-15T11:30:00",
      "expires_at": "2024-02-14T10:00:00",
      "user_agent": "Chrome on Windows",
      "is_current": true
    },
    {
      "session_id": "session_2",
      "created_at": "2024-01-14T15:00:00",
      "last_used": "2024-01-14T16:00:00",
      "expires_at": "2024-02-13T15:00:00",
      "user_agent": "Firefox on Mac",
      "is_current": false
    }
  ],
  "total_sessions": 2,
  "session_valid": true
}
```

---

## Управление сессиями (принудительное)

### Принудительный выход из сессии

**Endpoint:** `POST /internal/auth/logout`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса с сессией пользователя
- Декоратор `@require_valid_session`

**Описание:**
Позволяет сервису принудительно завершить пользовательскую сессию. Например, при подозрении на несанкционированный доступ или по запросу администратора.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session terminated successfully",
  "session_id": "идентификатор_сессии",
  "deleted": true
}
```

---

### Принудительный выход из всех сессий пользователя

**Endpoint:** `POST /internal/auth/logout-all`

**Требования:**
- Токен сервиса в заголовке `X-Service-Token`
- JSON в теле запроса с сессией пользователя
- Декоратор `@require_valid_session`

**Описание:**
Завершает все активные сессии пользователя. Используется при смене пароля, подозрении на взлом или при администрировании.

**Response (200 OK):**
```json
{
  "success": true,
  "message": "All sessions terminated successfully",
  "account_id": 123,
  "deleted": true
}
```

---

## Механизмы авторизации

### Для сервисов:

1. **API Key аутентификация** (для получения токена сервиса):
   ```
   X-API-Key: внутренний_ключ_из_конфигурации
   ```

2. **Service Token аутентификация** (для всех остальных операций):
   ```
   X-Service-Token: токен_полученный_из_get-service-token
   ```

### Для пользовательских сессий:

Все операции с пользовательскими сессиями требуют передачи данных сессии в JSON:
```json
{
  "session_id": "идентификатор_сессии_из_куки",
  "access_token": "access_токен_из_куки"
}
```

---

## Использование в микросервисной архитектуре

### Типичные сценарии использования:

1. **Сервис A** хочет проверить валидность сессии пользователя:
   - Вызывает `/internal/auth/validate-session`
   - Если сессия валидна, получает информацию о пользователе

2. **Сервис B** обнаруживает подозрительную активность:
   - Вызывает `/internal/auth/logout-all`
   - Принудительно завершает все сессии пользователя

3. **Новый микросервис** регистрируется в системе:
   - Администратор создает токен через `/internal/auth/get-service-token`
   - Сервис использует токен для всех последующих запросов

4. **Сервис аналитики** собирает информацию о сессиях:
   - Вызывает `/internal/auth/get-all-session-info`
   - Анализирует активность пользователей

---

## Форматы данных

### Сессионная информация в куках пользователя:

Формат куки `norbit.id`:
```
session_id:access_token
```

Где:
- `session_id` - уникальный идентификатор сессии (32 символа)
- `access_token` - JWT access токен

### JWT токены:

**Access токен:**
```json
{
  "type": "access",
  "account_id": 123,
  "public_id": "abc123def456",
  "session_id": "session_identifier",
  "exp": 1705312800,
  "iat": 1705311900,
  "jti": "unique_token_id"
}
```

**Refresh токен:**
```json
{
  "type": "refresh",
  "account_id": 123,
  "public_id": "abc123def456",
  "session_id": "session_identifier",
  "exp": 1707896700,
  "iat": 1705311900,
  "jti": "unique_token_id"
}
```

---

## Обработка ошибок

**Коды ответов для внутренних сервисов:**

- `200 OK` - успешное выполнение
- `400 Bad Request` - невалидные входные данные
- `401 Unauthorized` - невалидный API ключ или токен сервиса
- `404 Not Found` - ресурс не найден
- `500 Internal Server Error` - внутренняя ошибка сервера

**Формат ошибок:**
```json
{
  "error": "Описание ошибки",
  "session_valid": true/false  // для операций с сессиями
}
```

---

## Безопасность

### Меры безопасности для internal API:

1. **Двухуровневая аутентификация:**
   - API Key для получения токена
   - Service Token для всех остальных операций

2. **Валидация сессий:**
   - Все операции проверяют соответствие session_id и access_token
   - Проверяется срок действия сессии

3. **Изоляция данных:**
   - Сервисы могут получать только информацию о пользователях
   - Нельзя изменять пароли или основные данные аккаунтов

4. **Логирование:**
   - Все запросы логируются с идентификатором сервиса
   - Отслеживается использование токенов сервисов

---

## Интеграционные примеры

### Python пример для микросервиса:

```python
import requests

class AuthServiceClient:
    def __init__(self, service_token, base_url="http://auth-service"):
        self.service_token = service_token
        self.base_url = base_url
    
    def validate_session(self, session_id, access_token):
        """Проверяет валидность сессии пользователя"""
        response = requests.post(
            f"{self.base_url}/internal/auth/validate-session",
            headers={"X-Service-Token": self.service_token},
            json={
                "session_id": session_id,
                "access_token": access_token
            }
        )
        return response.json()
    
    def get_user_info(self, session_id, access_token):
        """Получает информацию о пользователе"""
        response = requests.post(
            f"{self.base_url}/internal/auth/get-account-info",
            headers={"X-Service-Token": self.service_token},
            json={
                "session_id": session_id,
                "access_token": access_token
            }
        )
        return response.json()
```

### Пример использования в middleware:

```python
from flask import request, g, jsonify

def require_auth_middleware():
    """Middleware для проверки аутентификации пользователя"""
    auth_client = current_app.auth_client
    
    # Получаем сессию из куки
    cookie_value = request.cookies.get('norbit.id')
    if not cookie_value:
        return jsonify({"error": "Authentication required"}), 401
    
    parts = cookie_value.split(':', 1)
    if len(parts) != 2:
        return jsonify({"error": "Invalid session cookie"}), 401
    
    session_id, access_token = parts
    
    # Проверяем сессию через auth service
    result = auth_client.validate_session(session_id, access_token)
    
    if not result.get('valid'):
        return jsonify({"error": "Invalid or expired session"}), 401
    
    # Сохраняем информацию о пользователе в контексте запроса
    user_info = auth_client.get_user_info(session_id, access_token)
    g.user = user_info.get('account')
    g.session_id = session_id
    
    return None  # Продолжаем обработку запроса
```