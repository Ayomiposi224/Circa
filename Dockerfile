FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api.py db.py mailer.py signup.py ratelimit.py ai_assist3.py phase2.py report.py ./
COPY dashboard.html confirm.html unsubscribe.html ./

RUN useradd --create-home --shell /usr/sbin/nologin circa
USER circa

EXPOSE 8000
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]