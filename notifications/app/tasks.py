import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from flask import current_app
from .utils import render_email_template

def send_verification_email(email: str, code: str, operation: str, **kwargs):
    """
    Отправляет email для верификации.
    **kwargs добавлено для совместимости с метаданными RQ (например, retries, retry_intervals).
    """
    try:
        template_data = render_email_template(code, operation)
        html_body = template_data['html']
        subject = template_data['subject']

        msg = MIMEText(html_body, 'html', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = formataddr((current_app.config['SENDER_NAME'], current_app.config['SENDER_EMAIL']))
        msg['To'] = email

        with smtplib.SMTP_SSL(
            current_app.config['SMTP_SERVER'],
            current_app.config['SMTP_PORT']
        ) as server:
            server.login(current_app.config['SMTP_LOGIN'], current_app.config['SMTP_PASSWORD'])
            server.sendmail(current_app.config['SENDER_EMAIL'], [email], msg.as_string())

        current_app.logger.info(f"Email sent to {email}")
    except Exception as e:
        current_app.logger.error(
            f"Failed to send email to {email}: {e}",
            exc_info=True
        )
        raise