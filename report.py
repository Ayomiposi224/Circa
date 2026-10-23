from db import get_connection

from datetime import datetime, timedelta
from mailer import send_email
from signup import build_unsubscribe_link
from db import get_signup_connection, get_lookup_connection


def get_last_report_time(cursor):
    cursor.execute("SELECT ran_at FROM report_runs ORDER BY ran_at DESC LIMIT 1")
    result = cursor.fetchone()

    if result:
        return result[0]
    else:
        return datetime.now() - timedelta(days=1)


def record_report_run(cursor):
    cursor.execute("INSERT INTO report_runs (ran_at) VALUES (NOW())")




def get_new_today(cursor, limit=10):
    last_report = get_last_report_time(cursor)
    cursor.execute("""
        SELECT title, source, cve_id, priority, priority_level, category, url, description
        FROM incidents
        WHERE created_at > %s
        ORDER BY priority DESC
        LIMIT %s
    """, (last_report, limit))
    return cursor.fetchall()

def get_still_critical(cursor, limit=5):
    cursor.execute("""
        SELECT title, source, cve_id, priority, priority_level, category, url, created_at, description
        FROM incidents
        WHERE priority_level = 'Critical'
        AND created_at::date != CURRENT_DATE
        ORDER BY created_at ASC
        LIMIT %s
    """, (limit,))
    return cursor.fetchall()

def summarize(description, max_length=150):
    if not description:
        return ""
    first_sentence = description.split(".")[0] + "."
    if len(first_sentence) > max_length:
        return first_sentence[:max_length] + "..."

    return first_sentence

def delete_stale_signups(cursor):
    cursor.execute(
        "DELETE FROM subscribers WHERE confirmed = FALSE AND created_at < NOW() - INTERVAL '24 hours'"
    )
    return cursor.rowcount



conn = get_connection()
cursor = conn.cursor()
removed = delete_stale_signups(cursor)
conn.commit()
print(f"Removed {removed} stale unconfirmed signups")

new_today = get_new_today(cursor)
still_critical = get_still_critical(cursor)


    

def format_report(new_today, still_critical):
    lines = []
    lines.append(f"=== CIRCA Daily Threat Report ===\n")

    lines.append(f"NEW TODAY ({len(new_today)})")
    for row in new_today:
        title, source, cve_id, priority, priority_level, category, url, description = row
        lines.append(f"[{priority_level}] {title} ({source})")
        lines.append(f"Category: {category}")
        lines.append(f"{url}")
        lines.append(f"Description: {summarize(description)}")
        lines.append("")  # blank line between entries

    lines.append(f"STILL CRITICAL (unresolved) ({len(still_critical)})")
    for row in still_critical:
        title, source, cve_id, priority, priority_level, category, url, created_at, description = row
        lines.append(f"[{priority_level}] {title} ({source})")
        lines.append(f"Category: {category}")
        lines.append(f"{url}")
        lines.append(f"First seen: {created_at}")
        lines.append(f"Description: {summarize(description)}")
        lines.append("")  # blank line between entries

    return "\n".join(lines)


report_text = format_report(new_today, still_critical)

cursor.execute("SELECT email, token FROM subscribers WHERE active = TRUE AND confirmed = TRUE")
recipients = cursor.fetchall()     

sent_count = 0
for email, token in recipients:
    footer = (
        "\n\n--\n"
        "You are receiving this because you subscribed to CIRCA.\n"
        f"To unsubscribe: {build_unsubscribe_link(token)}\n"
    )
    if send_email(email, "CIRCA Daily Threat Report", report_text + footer):
        sent_count += 1

print(report_text)
print(f"Sent to {sent_count} of {len(recipients)} subscribers")

if sent_count > 0:
    record_report_run(cursor)
    conn.commit()
else:
    print("Nobody received it; report run NOT recorded.")
