import os
import smtplib
from email.message import EmailMessage


def send_email(to, subject, body):
    # Credentials come from ~/.zshrc, never from this file.
    user = os.environ["CIRCA_MAIL_USER"]
    # Google displays app passwords with spaces; remove them to be safe.
    password = os.environ["CIRCA_MAIL_PASSWORD"].replace(" ", "")

    msg = EmailMessage()
    msg["From"] = f"CIRCA Alerts <{user}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(user, password)
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as e:
        print(f"Email to {to} failed: {e}")
        return False