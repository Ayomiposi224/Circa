# CIRCA

**Cyber Incident Report & Collection Assistant**

CIRCA is a threat-intelligence tool that automatically gathers public cybersecurity news and vulnerability data, stores it, emails it to subscribers, shows it on a dashboard, and answers questions about it through an AI chat.

## What it does

- Collects security incidents and vulnerabilities from public sources (CISA's Known Exploited Vulnerabilities list, the NVD vulnerability database and The Hacker News feed) every hour
- Stores them in a PostgreSQL database
- Emails a summary report to subscribers three times a day (07:00, 15:00 and 23:00)
- Has a dashboard where you can see live statistics, browse recent incidents and search them
- Has an AI chat where you can ask questions about the collected incidents in plain English

## How it works

   ![CIRCA architecture: public sources feed the collector, which writes to PostgreSQL; the web app serves visitors, and the report job emails subscribers](architecture.png)

   - The **collector** runs every hour, reads the public sources and saves new incidents in the database.
   - The **report job** emails a summary to subscribers three times a day.
   - The **web app** serves the dashboard, the signup and unsubscribe pages and the AI chat. It connects to the database as separate users, each allowed to do only its own job.

## Screenshots

![The CIRCA dashboard with live statistics, trend chart and the AI chat open](dashboard.png)

![The AI chat explaining why a vulnerability matters to an organisation](ai-chat.png)


## How to run it

You need Docker and Docker Compose.

1. Get the code:

   ```
   git clone https://github.com/Ayomiposi224/Circa.git
   cd Circa
   ```

2. Create your settings file and fill in your own values. Make each password long and random, for example with `openssl rand -hex 24`:

   ```
   cp .env.example .env
   ```

   `.env` holds passwords and API keys. It is never committed to Git.
   
   For a local run, set CIRCA_BASE_URL to http://127.0.0.1:8000.

   The dashboard works without an OpenAI key and mail login, but the AI chat will report that it is unavailable and no emails will be sent.
   
3. Start the database and wait until it is ready:

   ```
   docker compose up -d db
   ```
   Check that it says `healthy`:

   ```
   docker compose ps
   ```

4. Create the database users and tables:

   ```
   docker compose exec -T db psql -U postgres -d cyberwatch -v ON_ERROR_STOP=1 < roles.sql
   docker compose exec -T db psql -U postgres -d cyberwatch -v ON_ERROR_STOP=1 < schema.sql
   ```

5. Set the database users' passwords from your `.env`:

   ```
   sh set-passwords.sh
   ```

6. Start the app:

   ```
   docker compose up -d --build
   ```

7. Open the dashboard at http://127.0.0.1:8000
