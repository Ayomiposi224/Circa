from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from uuid import UUID
from db import get_readonly_connection, get_unsub_connection
from fastapi import BackgroundTasks
from pydantic import BaseModel
from signup import clean_email, create_signup, send_confirmation, find_token, send_unsubscribe_email
from fastapi import FastAPI, HTTPException, Request
from ratelimit import allow, MAX_PER_IP







app = FastAPI(title="CIRCA")


@app.get("/")
def home():
    return {"message": "CIRCA is running"}



@app.get("/incidents")
def list_incidents(level: str | None = None, limit: int = 50):
    limit = min(limit, 100)          # never allow huge requests

    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        sql = """SELECT id, title, source, url, category, priority_level,
                        cvss_score, published, created_at
                 FROM incidents"""
        params = []
        if level:
            sql += " WHERE priority_level = %s"
            params.append(level)
        sql += " ORDER BY priority DESC, created_at DESC LIMIT %s"
        params.append(limit)

        cursor.execute(sql, params)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        columns = [col[0] for col in cursor.description]
        incident = dict(zip(columns, row))

        cursor.execute("""SELECT vendor, product, version,
                                 version_start_including, version_end_excluding
                          FROM affected_products WHERE incident_id = %s""",
                       (incident_id,))
        columns = [col[0] for col in cursor.description]
        incident["affected_products"] = [dict(zip(columns, r)) for r in cursor.fetchall()]
        return incident
    finally:
        conn.close()


@app.get("/dashboard")
def dashboard():
    return FileResponse("dashboard.html")


@app.get("/unsubscribe")
def unsubscribe_page():
    return FileResponse("unsubscribe.html")

@app.post("/unsubscribe")
def unsubscribe(token: UUID):
    conn = get_unsub_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM subscribers WHERE token = %s", (str(token),))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Invalid link")
        conn.commit()
        return {"message": "You have been unsubscribed."}
    finally:
        conn.close()

@app.get("/stats")
def stats():
    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""SELECT priority_level, COUNT(*)
                          FROM incidents GROUP BY priority_level""")

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for level, count in cursor.fetchall():
            if level in counts:
                counts[level] = count
        return counts
    finally:
        conn.close()

 
@app.get("/stats/categories")
def stats_categories():
    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COALESCE(category, 'other') AS category, COUNT(*) AS count
            FROM incidents
            GROUP BY 1
            ORDER BY count DESC
        """)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()
@app.get("/stats/summary")
def stats_summary():
    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS new_24h,
                   COUNT(DISTINCT source) AS sources
            FROM incidents
        """)
        new_24h, sources = cursor.fetchone()
        return {"new_24h": new_24h, "sources": sources}
    finally:
        conn.close()


@app.get("/stats/trend")
def stats_trend():
    conn = get_readonly_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT created_at::date AS day, priority_level, COUNT(*) AS count
            FROM incidents
            WHERE created_at >= CURRENT_DATE - 6
            GROUP BY 1, 2
            ORDER BY 1
        """)
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()

class SubscribeRequest(BaseModel):
    email: str


NEUTRAL_MESSAGE = (
    "If this address can be subscribed, a confirmation email is on its way. "
    "Check your inbox."
)



class UnsubscribeRequest(BaseModel):
    email: str


UNSUB_REQUEST_MESSAGE = (
    "If this address is subscribed, an email with an unsubscribe link is on its way. "
    "Check your inbox."
)

@app.post("/unsubscribe-request")
def unsubscribe_request(request: UnsubscribeRequest, background_tasks: BackgroundTasks, http_request: Request):
    check_visitor_limit(http_request)
    try:
        email = clean_email(request.email)
    except ValueError:
        raise HTTPException(status_code=400, detail="That doesn't look like an email address.")

    token = find_token(email)
    if token and allow("email:" + email, 1):      # one unsubscribe email per address per window
        background_tasks.add_task(send_unsubscribe_email, email, token)
    return {"message": UNSUB_REQUEST_MESSAGE}


def check_visitor_limit(http_request: Request):
    ip = http_request.client.host if http_request.client else "unknown"
    if not allow("ip:" + ip, MAX_PER_IP):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in a few minutes.")
    
    
@app.post("/subscribe")
def subscribe(request: SubscribeRequest, background_tasks: BackgroundTasks, http_request: Request):
    check_visitor_limit(http_request)
    try:

        email = clean_email(request.email)
    except ValueError:
        raise HTTPException(status_code=400, detail="That doesn't look like an email address.")

    token = create_signup(email)
    if token:
        background_tasks.add_task(send_confirmation, email, token)

    return {"message": NEUTRAL_MESSAGE}

@app.get("/confirm")
def confirm_page():
    return FileResponse("confirm.html")

@app.post("/confirm")
def confirm(token: UUID):
    conn = get_unsub_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE subscribers SET confirmed = TRUE WHERE token = %s",
            (str(token),),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Invalid link")
        conn.commit()
        return {"message": "Your subscription is confirmed."}
    finally:
        conn.close()



from ai_assist3 import handle_question
# get_readonly_connection should already be imported from db

MAX_ASK_PER_IP = 10
MAX_ASK_PER_DAY = 200
MAX_QUESTION_CHARS = 300
DAY_SECONDS = 86400

class AskRequest(BaseModel):
    question: str

def check_ask_limits(http_request: Request):
    ip = http_request.client.host if http_request.client else "unknown"
    if not allow("ask:" + ip, MAX_ASK_PER_IP):
        raise HTTPException(status_code=429, detail="Too many questions. Try again in a few minutes.")
    if not allow("ask:all", MAX_ASK_PER_DAY, DAY_SECONDS):
        raise HTTPException(status_code=429, detail="The assistant has reached its daily limit. Please try again tomorrow.")

@app.post("/ask")
def ask(request: AskRequest, http_request: Request):
    question = request.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Please type a question.")
    if len(question) > MAX_QUESTION_CHARS:
        raise HTTPException(status_code=400, detail="Please keep your question under 300 characters.")
    check_ask_limits(http_request)

    conn = get_readonly_connection()
    try:
        cur = conn.cursor()
        answer = handle_question(question, cur)
    finally:
        conn.close()
    return {"answer": answer}