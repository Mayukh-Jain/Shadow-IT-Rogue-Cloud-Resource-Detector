# Capstone Project: Status & Completion Plan

This document serves as the master blueprint for the Shadow IT Risk Scoring pipeline. It details the current project structure, all the enterprise-grade engineering accomplished so far, and the exact step-by-step instructions to build the final component: **The Slack Bot (Person 4)**.

---

## ✅ Phase 1: Completed Work

We have successfully built, secured, and integrated the first 4 components of the pipeline.

### 1. The Shared Database (`shared/`)
- **Status:** COMPLETED 🟢
- **Details:** Built `local.db` using SQLite. Engineered a strict `schema.sql` containing `resources`, `risk_scores`, and `approvals` tables. 
- **Hardening:** Implemented `PRAGMA foreign_keys = ON`, `UNIQUE` resource ID constraints, and bulletproof timestamp parsing.

### 2. Cloud Detection Engine (`detection/`)
- **Status:** COMPLETED 🟢
- **Details:** `scanner.py` successfully authenticates with AWS using `boto3` to find rogue EC2, S3, and RDS resources based on `policy.yaml`.
- **Hardening:** Implemented mathematical **True Idle Detection** using actual CloudWatch metrics (`CPUUtilization` and `DatabaseConnections`) rather than relying on naive AWS status states. Added dynamic region support and resilient `ClientError` bypassing.

### 3. ML Risk Scoring Engine (`ml-scoring/`)
- **Status:** COMPLETED 🟢
- **Details:** `generate_synthetic_data.py` created 1,500 training rows. `train_model.py` built the Random Forest Regressor (`model.pkl`). `score_resources.py` scores the live database resources and assigns HIGH/MEDIUM/LOW buckets.
- **Hardening:** Completely solved ML Target Leakage by perfectly balancing the formula weights to `100`. Prevented Database pollution by upgrading the scoring script to use `INSERT OR REPLACE` logic.

### 4. LLM Explainability (`llm-explainability/`)
- **Status:** COMPLETED 🟢
- **Details:** `explainer.py` queries unexplained risks and uses LangChain to connect to OpenRouter (`gpt-4o-mini`). It generates concise 2-sentence remediation plans and updates the database.
- **Hardening:** Patched LangChain memory leaks by pulling the chain constructor out of loops. Added strict financial safeguards (`max_tokens=100`) to prevent API bill runaways.

### 5. Master Orchestrator
- **Status:** COMPLETED 🟢
- **Details:** Wrote `run_pipeline.py` in the root folder, allowing the entire pipeline to be executed sequentially in either `--mock` or live AWS modes.

---

## 🚧 Phase 2: Remaining Work (The Slack Bot)

**Objective (Person 4):** Build a Slack Bot that alerts the SRE team when a `HIGH` risk resource is detected. The bot must present interactive buttons (e.g., "Accept Risk" or "Remediate") and save the human's decision back into the `approvals` database table.

### Step-by-Step Implementation Plan

#### Step 1: Slack API Setup (Manual)
1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new App.
2. Under **Socket Mode**, toggle it ON (this allows the bot to run locally without a public web server).
3. Under **OAuth & Permissions**, add these Scopes: `chat:write` (to send messages).
4. Under **Interactivity & Shortcuts**, toggle Interactivity ON.
5. **Tokens Needed:** You will need to copy your `xoxb-...` (Bot Token) and `xapp-...` (App-Level Token) into a new `.env` file.

#### Step 2: Initialize the Slack Bot Module
1. Create a new folder: `d:\Projects\capstone\slack-bot`
2. Create `slack-bot/requirements.txt`:
   ```text
   slack_bolt
   python-dotenv
   ```
3. Create `slack-bot/.env`:
   ```env
   SLACK_BOT_TOKEN=xoxb-your-bot-token
   SLACK_APP_TOKEN=xapp-your-app-token
   SLACK_CHANNEL_ID=C1234567890
   ```

#### Step 3: Write the Bot Code (`slack-bot/bot.py`)
The code must accomplish three distinct things:
1. **The Poller:** A function that periodically checks the `risk_scores` table for any `HIGH` risk resources that do **not** yet have a matching row in the `approvals` table.
2. **The Messenger:** Use Slack Block Kit to send a beautifully formatted message to the channel containing:
   - Resource Name & ID
   - The ML Score & The LLM Explanation
   - Two interactive buttons: `[Approve (False Positive)]` and `[Terminate Resource]`
3. **The Listener (`@app.action`)**: A webhook listener using `slack_bolt.App`. When a user clicks a button, the bot must:
   - Acknowledge the click.
   - Update the Slack message to say "Decision made by @username".
   - `INSERT` a new row into the shared `approvals` table (saving the `resource_id`, the `sre_name`, the `action_taken`, and the timestamp).

#### Step 4: Final Integration
1. Test the Slack Bot locally using the Mock data generated in Phase 1.
2. Once the bot successfully updates the `approvals` table upon button click, update the master `run_pipeline.py` script to include `bot.py` (or keep the bot running continuously in the background).
3. The Capstone Project is officially **Finished**!
