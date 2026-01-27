from typing import Dict
from flask import render_template_string


def render_email_template(code: str, operation: str) -> Dict[str, str]:
    """Рендерит письмо подтверждения из локального шаблона."""

    # Путь к шаблону
    template_path = "./app/templates/mail.html"

    try:
        # Читаем содержимое HTML-шаблона
        with open(template_path, 'r', encoding='utf-8') as f:
            html_template = f.read()

        # Определяем заголовок письма в зависимости от операции
        if operation == "registration":
            confirmation_title = "Подтверждение регистрации"
            operation_description = "регистрации"
        elif operation == "login":
            confirmation_title = "Вход"
            operation_description = "входа"
        elif operation == "reset":
            confirmation_title = "Сброс пароля"
            operation_description = "сброса пароля"
        elif operation == "verify":
            confirmation_title = "Подтверждение входа"
            operation_description = "подверждения входа"
        elif operation == "delete":
            confirmation_title = "Подтверждение удаления"
            operation_description = "подтверждения удаления аккаунта"
        else:
            confirmation_title = "Подтверждение действия"
            operation_description = "действия"

        # Разбиваем код на отдельные цифры
        digits = list(code)
        # Добавляем недостающие нули, если код короче 6 символов
        while len(digits) < 6:
            digits.append('')

        # Подготавливаем контекст для подстановки
        context = {
            'confirmation_title': confirmation_title,
            'operation_description': operation_description,
            'code': code,
            'digit0': digits[0] if len(digits) > 0 else '',
            'digit1': digits[1] if len(digits) > 1 else '',
            'digit2': digits[2] if len(digits) > 2 else '',
            'digit3': digits[3] if len(digits) > 3 else '',
            'digit4': digits[4] if len(digits) > 4 else '',
            'digit5': digits[5] if len(digits) > 5 else '',
        }

        # Рендерим шаблон с подстановкой переменных
        html_content = render_template_string(html_template, **context)

        # Создаем тему письма
        if operation == "registration":
            subject = f"Код подтверждения для регистрации: {code}"
        elif operation == "login":
            subject = f"Код для входа: {code}"
        elif operation == "reset":
            subject = f"Код для сброса пароля: {code}"
        elif operation == "verify":
            subject = f"Код подтверждения входа: {code}"
        elif operation == "delete":
            subject = f"Код подтверждения удаления аккаунта: {code}"
        else:
            subject = f"Код подтверждения: {code}"

        return {
            "html": html_content,
            "subject": subject
        }

    except FileNotFoundError:
        raise Exception(f"Шаблон не найден по пути: {template_path}")
    except Exception as e:
        raise Exception(f"Ошибка рендеринга шаблона: {e}")