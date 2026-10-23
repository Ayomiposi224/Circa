from psycopg2 import errors
from db import get_signup_connection
import os
from mailer import send_email
from db import get_signup_connection, get_lookup_connection

def clean_email(raw):
    email = raw.strip().lower()

    # Reject any whitespace inside (space, tab, newline) and anything
    has_whitespace = any(ch.isspace() for ch in email)
    if has_whitespace or email.count("@") != 1:
        raise ValueError("Invalid email address")
    name, domain = email.split("@")
    if name == "" or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Invalid email address")

    return email




def create_signup(email):
    conn = get_signup_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO subscribers (email) VALUES (%s) RETURNING token",
            (email,),
        )
        token = cursor.fetchone()[0]
        conn.commit()
        return str(token)
    except errors.UniqueViolation:
        conn.rollback()
        return None
    finally:
        conn.close()




def get_base_url():
    return os.environ.get("CIRCA_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def build_confirm_link(token):
    return f"{get_base_url()}/confirm?token={token}"


def build_unsubscribe_link(token):
    return f"{get_base_url()}/unsubscribe?token={token}"


def send_confirmation(email, token):
    link = build_confirm_link(token)
    subject = "Confirm your CIRCA subscription"
    body = (
        "Someone asked to receive CIRCA threat reports at this address.\n\n"
        "To confirm it was you, open this link:\n"
        f"{link}\n\n"
        "If this wasn't you, ignore this email. Nothing will be sent to you."
        "This link works for 24 hours.\n\n"
    )
    send_email(email, subject, body)

def find_token(email):
    conn = get_lookup_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT token FROM subscribers WHERE email = %s",
            (email,),
        )
        row = cursor.fetchone()
        if row is None:
            return None      # nothing found
        return str(row[0])
    finally:
        conn.close()


def send_unsubscribe_email(email, token):
    link = build_unsubscribe_link(token)
    subject = "Unsubscribe from CIRCA"
    body = (
        "Someone asked to unsubscribe this address from CIRCA threat reports.\n\n"
        "To confirm it was you, open this link:\n"
        f"{link}\n\n"
        "If this wasn't you, ignore this email. You will keep receiving reports."
    )
    send_email(email, subject, body)