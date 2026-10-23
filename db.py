import psycopg2
import os
DB_HOST = os.environ.get("CIRCA_DB_HOST", "localhost")

def get_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberwatch_app",
        password=os.environ["CIRCA_DB_PASSWORD"],
        host=DB_HOST,
    )




def insert_affected_products(cursor, incident_id, affected_products):
    for product in affected_products:
        cursor.execute("""
            INSERT INTO affected_products (incident_id, vendor, product, version, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            incident_id,
            product.get("vendor"),
            product.get("product"),
            product.get("version"),
            product.get("versionStartIncluding"),
            product.get("versionStartExcluding"),
            product.get("versionEndIncluding"),
            product.get("versionEndExcluding")
        ))

def insert_incident(cursor, incident, cve_id):
    cursor.execute("SELECT id FROM incidents WHERE cve_id = %s", (cve_id,))
    existing = cursor.fetchone()

    if cve_id and existing:
        cursor.execute("""
            UPDATE incidents SET
                vendor = %s,
                product = %s,
                required_action = %s,
                due_date = %s,
                date_added = %s,
                ransomware_use = %s,
                priority = %s,
                priority_level = %s,
                category = %s
            WHERE cve_id = %s
        """, (
            incident.get("vendor"),
            incident.get("product"),
            incident.get("required_action"),
            incident.get("due_date"),
            incident.get("date_added"),
            incident.get("ransomware_use"),
            incident.get("priority"),
            incident.get("priority_level"),
            incident.get("category"),
            cve_id
            
        ))
        cursor.execute("DELETE FROM affected_products WHERE incident_id = %s", (existing[0],))
        insert_affected_products(cursor, existing[0], incident.get("affected_products", []))

    else:
        cursor.execute("""
            INSERT INTO incidents (title, source, url, type, description, published, cvss_score, priority, severity, priority_level, category, vendor, product, required_action, due_date, date_added, ransomware_use, cve_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            ON CONFLICT (url) DO UPDATE SET
            vendor = EXCLUDED.vendor,
            product = EXCLUDED.product,
            required_action = EXCLUDED.required_action,
            due_date = EXCLUDED.due_date,
            date_added = EXCLUDED.date_added,
            ransomware_use = EXCLUDED.ransomware_use,
            priority = EXCLUDED.priority,
            priority_level = EXCLUDED.priority_level,
            category = EXCLUDED.category
            returning id
        """, (
            incident.get("title"),
            incident.get("source"),
            incident.get("url"),
            incident.get("type"),
            incident.get("description"),
            incident.get("published"),
            incident.get("cvss_score"),
            incident.get("priority"),
            incident.get("severity"),
            incident.get("priority_level"),
            incident.get("category"),
            incident.get("vendor"),
            incident.get("product"),
            incident.get("required_action"),
            incident.get("due_date"),
            incident.get("date_added"),
            incident.get("ransomware_use"),
            cve_id
        ))
        incident_id = cursor.fetchone()[0]
        insert_affected_products(cursor, incident_id, incident.get("affected_products", []))


def get_readonly_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberwatch_readonly",
        password=os.environ["CIRCA_DB_RO_PASSWORD"],
        host=DB_HOST,
    )

def get_unsub_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberwatch_unsub",
        password=os.environ["CIRCA_DB_UNSUB_PASSWORD"],
        host=DB_HOST,
    )

def get_signup_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberwatch_signup",
        password=os.environ["CIRCA_DB_SIGNUP_PASSWORD"],
        host=DB_HOST,
    )

def get_lookup_connection():
    return psycopg2.connect(
        dbname="cyberwatch",
        user="cyberwatch_lookup",
        password=os.environ["CIRCA_DB_LOOKUP_PASSWORD"],
        host=DB_HOST,
    )