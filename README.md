# MailGuard v2.1
Self-hosted, human-in-the-loop IMAP spam quarantine/review. Automated classification can only move suspected mail to SpamReview. Human review is required to move it to Trash, and MailGuard never issues EXPUNGE.

## v2.1 changes
- New signed, explainable hybrid classifier inspired by mature multi-signal filtering: authentication, sender identity, HTML/MIME structure, URLs, attachments, upstream spam headers, promotional/urgency/financial language and negative evidence for authentication passes.
- Default threshold reduced from 75 to 45 because v2 scores are calibrated on a wider set of independent signals. Tune it using real scan logs.
- Classifier versioning (`hybrid-v2.1`). Existing source-folder messages can be explicitly reclassified after an upgrade.
- New `Scans & logs` UI with scan history, per-message classifications, scores, rule contributions, errors, and score distribution.
- Container logs include scan ID, UID, result, score, sender, truncated subject, and triggered signal names. They never include credentials or full body text.
- Existing SQLite databases are migrated in place. The Docker named volume is retained during normal upgrades.

This design adopts the useful architecture of combining many independent signals rather than copying an SMS-trained model into an email system. It leaves a clean classifier boundary for a future email-trained TF-IDF/LinearSVC, SpamAssassin, or Rspamd backend.

## Upgrade from the previous GitHub version
Back up the volume and your `.env` first. Then:
```bash
git pull --ff-only
docker compose up -d --build
```
Do not use `docker compose down -v`.

After login, open Dashboard and click **Reclassify source mailbox**. This matters for the 5,000 messages already recorded by the previous classifier. Reclassification applies only to messages that are still present in the configured source mailbox. It can quarantine newly detected spam but still cannot move anything directly to Trash.

Then open **Scans & logs**, select the scan, and inspect its score distribution and individual rule contributions. This is the preferred way to tune the threshold rather than guessing.

## New deployment
```bash
git clone https://github.com/YOUR-USER/mailguard.git
cd mailguard
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# put the generated APP_SECRET in .env
docker compose up -d --build
```
Open `http://DOCKER-HOST:8080/setup`.

## Classifier approach
The classifier is intentionally explainable. Each fired signal has a signed score. Spam-like evidence adds points and ham-like evidence can subtract points. The total is clamped to 0-100 and compared to the configured threshold. No one body keyword is sufficient by itself. Examples include DMARC/SPF/DKIM failures or passes, sender/Reply-To mismatch, IP/punycode/shortened URLs, link density, HTML/image structure, risky attachment extensions, upstream `X-Spam-*` evidence, urgency and promotional patterns.

This is still a local heuristic classifier, not a claim of state-of-the-art ML accuracy. Your throwaway spam mailbox is the acceptance test: inspect false negatives and false positives in the detailed scan log and tune from evidence. A future statistical classifier should be trained on labeled *email*, not only SMS data.

## Logs and privacy
The web UI stores scan metadata and a compact signal list. SQLite stores only the existing truncated preview, not complete mail bodies or attachment contents. stdout records classifier decisions but not credentials, tokens, or full bodies:
```bash
docker compose logs -f mailguard
```
The per-message web log shows UID, sender, subject, final score/result, and every rule contribution.

## Safety
- Automated classification never moves mail to Trash.
- Review messages are not selected by default.
- Delete requires explicit confirmation and means move to Trash.
- No EXPUNGE implementation exists.
- Email HTML is never rendered and external resources are never loaded.
- Attachment contents are not downloaded for classification; only MIME/message payload handling needed for text and metadata is performed.

## Test
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
```
GitHub Actions runs pytest and a Docker build on pushes and pull requests.
