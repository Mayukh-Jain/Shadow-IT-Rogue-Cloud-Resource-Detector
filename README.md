# Slack Bot & SRE Approval Workflow (Person 4)

This module provides the **Human-in-the-Loop Slack Bot & Backend Approval Engine** for the **Shadow IT / Rogue Cloud Resource Detector** capstone project.

---

## 🌟 Overview & Architecture

Whenever the detection and ML pipeline identifies an AWS resource with a **HIGH** risk score, this service:
1. Formats a structured Slack **Block Kit** alert with resource details, ML risk score (0–100), and AI-generated remediation guidance.
2. Posts the alert to a dedicated Slack channel (`SLACK_CHANNEL`).
3. Inserts a `PENDING` approval record into the shared SQLite `approvals` database table.
4. Provides interactive buttons for an SRE:
   - **`[Approve]`**: Confirms resource is legitimate/accepted; updates status to `APPROVED`.
   - **`[Reject]`**: Confirms resource is rogue/unauthorized; updates status to `REJECTED`.
   - **`[Snooze]`**: Temporarily suppresses notifications for 24 hours; updates status to `SNOOZED`.
5. Updates the original Slack message dynamically to display the SRE decision, reviewer username, and timestamp while disabling the interactive buttons to maintain an immutable audit trail.
6. Operates in **MOCK / SIMULATION mode** if Slack credentials are not yet configured, allowing 100% offline development, local pipeline execution, and viva demonstration.

```mermaid
sequenceDiagram
    participant P as Pipeline / Scorer
    participant DB as Shared SQLite DB
    participant SB as Slack Bot Service
    participant S as Slack Channel
    participant SRE as Human SRE

    P->>DB: Write Flagged Resource + HIGH Risk Score
    SB->>DB: Query Unnotified HIGH-Risk Findings
    SB->>S: Post Block Kit Alert (Approve/Reject/Snooze)
    SB->>DB: Insert PENDING Record in `approvals`
    SRE->>S: Click [Approve / Reject / Snooze]
    S->>SB: Interactive Action Webhook Payload
    SB->>DB: UPDATE `approvals` (status, sre_name, decided_at)
    SB->>S: Update Slack Message (Remove Buttons, Add Decision Badge)
```

---

## 📁 Module Structure

```
slack-bot/
├── app.py               # FastAPI server, Slack action listeners, webhook routes, CLI entrypoint
├── slack_client.py      # Bolt initialization, HMAC-SHA256 signature verification, message posting/updates
├── block_templates.py   # Reusable Slack Block Kit templates for alerts and decision audit badges
├── requirements.txt     # Module dependencies (slack_bolt, slack_sdk, fastapi, uvicorn, python-dotenv)
└── README.md            # Complete user and setup guide
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory (or inside `slack-bot/`) based on `.env.example`:

```env
# Slack Bot OAuth Token (api.slack.com -> OAuth & Permissions)
SLACK_BOT_TOKEN=xoxb-your-bot-token

# Slack Signing Secret (api.slack.com -> Basic Information -> App Credentials)
SLACK_SIGNING_SECRET=your-slack-signing-secret

# Target Slack Channel (Name or ID, e.g. #shadow-it-alerts or C0123456789)
SLACK_CHANNEL=#shadow-it-alerts

# (Optional) App-Level Token for Socket Mode
SLACK_APP_TOKEN=xapp-your-app-token

# Server Port (default: 8000)
PORT=8000
```

> **Note:** If `SLACK_BOT_TOKEN` or `SLACK_SIGNING_SECRET` are not set (or contain placeholder text), the bot automatically runs in **MOCK / SIMULATION mode**. All database updates, deduplication logic, and state transitions will function without throwing errors.

---

## 🛠️ Slack App Setup (When Adding Real Slack Credentials)

Follow these steps once you are ready to connect to a live Slack workspace:

### 1. Create App
1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** -> **From scratch**.
2. Name your app (e.g. `Shadow IT Bot`) and choose your workspace.

### 2. Configure Scopes (OAuth & Permissions)
Under **Features** -> **OAuth & Permissions** -> **Bot Token Scopes**, add:
- `chat:write` (Allows the bot to post and update alert messages)
- `chat:write.public` (Allows posting to public channels without manual invite)
- `incoming-webhook` (Optional)

Install the app to your workspace and copy the **Bot User OAuth Token** (`xoxb-...`) to `SLACK_BOT_TOKEN`.

### 3. Get Signing Secret
Under **Settings** -> **Basic Information** -> **App Credentials**, copy the **Signing Secret** to `SLACK_SIGNING_SECRET`.

### 4. Enable Interactivity
1. Start your local Slack server:
   ```bash
   python slack-bot/app.py --server
   ```
2. In a separate terminal, expose your local port 8000 using `ngrok`:
   ```bash
   ngrok http 8000
   ```
3. Under **Features** -> **Interactivity & Shortcuts**:
   - Turn **Interactivity** ON.
   - Set **Request URL** to: `https://<your-ngrok-subdomain>.ngrok-free.app/slack/events`
   - Click **Save Changes**.

---

## 🚀 How to Run

### 1. Dispatch Alerts for Existing High-Risk DB Records
```powershell
python slack-bot/app.py
```

### 2. Run in Simulation / Demo Mode (Safe for Viva / Demos)
Triggers a synthetic high-risk finding without touching live AWS resources:
```powershell
python slack-bot/app.py --simulate
```

### 3. Start the Webhook Server
Starts the FastAPI + Bolt listener on port 8000:
```powershell
python slack-bot/app.py --server
```

### 4. Run the Full Master Pipeline
Executes the detection, ML scoring, LLM explanation, and Slack alert dispatch in sequence:
```powershell
# With mock injected data:
python run_pipeline.py --mock

# With live AWS scanning:
python run_pipeline.py
```

---

## 🧪 Testing

The test suite contains 22 unit and integration tests covering message generation, signature verification, SRE decisions, deduplication, and API routes.

Run all tests with:
```powershell
python -m pytest tests/test_slack_bot.py -v
```

---

## 🔒 Security Features Implemented

1. **HMAC-SHA256 Signature Verification**: Validates `X-Slack-Signature` using constant-time comparison (`hmac.compare_digest`) against `SLACK_SIGNING_SECRET`.
2. **Replay Attack Defense**: Checks `X-Slack-Request-Timestamp` and rejects requests older than 300 seconds.
3. **No Secret Leakage**: Tokens and secrets are sanitized and never logged to stdout or log files.
4. **Duplicate Alert Suppression**: SQLite query checks `approvals` table before alerting to prevent alert spam across repeated pipeline runs.
5. **Human-in-the-Loop Safeguard**: Decisions require explicit human action (`Approve`, `Reject`, or `Snooze`) before database state transition.
