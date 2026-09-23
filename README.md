# MailGuard

Self-hosted, human-in-the-loop IMAP spam quarantine and review. Automatic classification may move suspected spam to `SpamReview`, but **only human review can move messages to Trash**. MailGuard deliberately does not provide an EXPUNGE operation.

## Architecture

One Docker container runs FastAPI, a server-rendered web UI and the IMAP integration. SQLite is stored in `/data` on a named Docker volume. Mail bodies are not retained in the database. The classifier is modular and the initial implementation combines authentication, identity, URL-domain and attachment signals rather than keyword-only matching.

## Deploy directly from GitHub

Requirements: Git, Docker Engine, and Docker Compose v2.

```bash
git clone https://github.com/YOUR-USER/mailguard.git
cd mailguard
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value into `APP_SECRET` in `.env`. Adjust `TRUSTED_HOSTS` to include the hostname or IP used to open MailGuard. Then:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f mailguard
```

Open `http://DOCKER-HOST:8080/setup` and create the administrator, then configure the IMAP account under Settings.

### Update from GitHub

```bash
git pull --ff-only
docker compose up -d --build
```

The named `mailguard-data` volume survives normal container recreation. Do **not** use `docker compose down -v` unless you intentionally want to delete the SQLite state.

### Stop/start

```bash
docker compose down
docker compose up -d
```

## Secrets

Never commit `.env`. It is excluded by both `.gitignore` and `.dockerignore`. `APP_SECRET` protects sessions and derives the key used to encrypt the stored IMAP password. Back it up separately. Losing/changing it makes an existing encrypted IMAP password unreadable. IMAP credentials are entered in the web UI, not committed to Git.

With HTTPS at a reverse proxy, set `COOKIE_SECURE=true` and restrict `TRUSTED_HOSTS` to the public hostname. Do not expose plain HTTP to an untrusted network.

## Mail safety

MailGuard uses IMAP UIDs and UIDVALIDITY. Suspected mail is moved to the configured review folder. Keep returns it to the source folder. Delete moves it to Trash. Where IMAP MOVE is unavailable, the adapter copies the specific UID and applies `\Deleted` to that specific source UID; it never calls `EXPUNGE`.

Email content is hostile input. The UI displays escaped text; it never renders mail HTML, downloads remote images, follows links, executes attachments, or passes email content to a shell.

## Tests

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

GitHub Actions runs the tests and a Docker image build on pushes and pull requests.

## Health

`GET /health` verifies that the application and SQLite database are available. Remote IMAP downtime does not by itself make the Docker container unhealthy.

## Repository contents

```text
app/                  application
app/templates/        web UI
app/static/           CSS/JavaScript
tests/                automated tests
.github/workflows/    GitHub CI
Dockerfile
docker-compose.yml
.env.example
.gitignore
.dockerignore
README.md
```

## Before production use

Test against your specific IMAP provider using a non-critical mailbox first. Providers vary in MOVE, UIDPLUS, folder naming, authentication and retention behavior. Back up the Docker volume and `APP_SECRET` before upgrades.
