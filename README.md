
# AI Email Spam & Threat Detection System

Mailwatch is a locally hosted, read-only email analysis MVP built with FastAPI, React/Vite, SQLite, Google OAuth for Gmail read access, and the Hugging Face DistilBERT spam classifier.

## Features

- Paste an email or load a saved `.eml` message.
- Connect Gmail and sync/scan the 10 newest Inbox messages after the account owner grants read-only access.
- Inspect email text for common social-engineering phrases and URLs for visible risk indicators. Links are never opened.
- Optionally look up SPF, DMARC, and a DKIM selector's DNS record. These lookups check for published records; they do not authenticate the message.
- Run the DistilBERT spam classifier on every manual or Gmail scan.
- Save a local scan report and dashboard counts in SQLite. Message body text and raw headers are not stored in scan history.
- View or delete saved reports.

## Run on Linux

Homebrew and Ollama are not required by Mailwatch.

### 1. Install and start the backend

Open a terminal in the project folder. If the prompt shows `(base)`, deactivate Conda first:

```bash
conda deactivate
```

Create the project environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements.txt
```

Install the CPU-only PyTorch build because this app runs the classifier on CPU. See the [official PyTorch installation selector](https://pytorch.org/get-started/locally/) if you need a different build.

Start the API:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Keep this terminal open. API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Install and start the dashboard

Open a second terminal in the project folder:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3778`. This matches the Authorized JavaScript origin shown in your Google OAuth client.

### 3. Run a first scan

Paste a subject and body, or use the file picker to load a text-based `.eml` file up to 1 MB. The first scan downloads the classifier; later scans use its local cache. The report and counters are saved locally.

## Connect Gmail

The supplied OAuth **client ID** is stored in `frontend/.env.local`, which is ignored by Git. A client ID is public browser configuration; do not put a client secret in the React app. Gmail access uses Google's `gmail.readonly` scope. The access token stays in browser memory, Gmail messages are fetched by the browser, and message text is sent to the local API for analysis. The app does not save message bodies or modify Gmail. “Clear session” clears the browser's token; remove the app from your Google Account security settings to revoke its grant.

In Google Cloud Console:

1. Select the project that owns the supplied OAuth client ID and enable the Gmail API.
2. Configure the OAuth consent screen. For personal testing, add your Gmail account as a test user if the app is in Testing mode.
3. In the OAuth client credentials, use a **Web application** client and add these Authorized JavaScript origins:
   - `http://localhost:3778`
4. Restart the Vite dev server if it was already running, reload the page, and choose **Sign in with Google**. Accept the read-only Gmail permission.
5. Choose **Sync and scan inbox** to analyze the 10 newest Inbox messages. Gmail's message list supplies IDs first; the app then fetches the selected message details for local analysis.

Google classifies `gmail.readonly` as a restricted scope. Testing users may see an unverified-app screen, and publishing the app to other users can require Google's OAuth verification. See Google's [Gmail scope requirements](https://developers.google.com/workspace/gmail/api/auth/scopes) and [Gmail message list API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list).

## Spam classification

Every scan uses `adevferjani/distilbert-spam-ceas08`. The first scan downloads it from Hugging Face; later scans use the local cache. It runs on CPU and may take a while the first time.

The model card describes a 67M-parameter English email classifier trained on CEAS-08. It reports F1 of 0.78 on Enron and 0.60 on SpamAssassin and says the model is for educational/research use, not production. Class names are read from the downloaded model configuration. If they are generic, set `HF_SPAM_LABEL_ID` in `.env` only after you verify the displayed class mapping.

### DNS record lookup

Enable **Check sender DNS records** to query the From domain for SPF and DMARC TXT records, and the DKIM selector from a `DKIM-Signature` header when one is present. A DNS record being present does not prove that this particular message passed authentication. Authentication-Results values are shown as reported in the supplied headers and are not independently verified.

## Production build

Build the frontend bundle:

```bash
cd frontend
npm run build
cd ..
```

Then start FastAPI using the backend command above and open `http://127.0.0.1:8000`. FastAPI serves the built dashboard when `frontend/dist` exists.

## Project structure

```text
backend/app/       FastAPI routes, local storage, email parsing, URL/auth checks, model clients
frontend/src/      React dashboard
spam_demo.py       Standalone first-milestone model CLI
data/              Local SQLite database, created on first API start
```

## Scope and safety

This is a runnable local MVP, not a production mail gateway. Gmail read-only sync is implemented; Microsoft accounts and IMAP are not. The app does not inspect attachment contents, call VirusTotal, or cryptographically validate DKIM. It does not click links, execute attachments, send email, or move/delete mailbox messages. Optional DNS checks contact the configured DNS resolver; the email body is not sent to DNS. The first Hugging Face model download contacts Hugging Face. Mailwatch no longer uses Ollama.
