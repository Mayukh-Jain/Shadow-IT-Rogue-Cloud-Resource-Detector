"""
FastAPI Backend & Slack Interactive Handler for Shadow IT / Rogue Cloud Resource Detector.
Manages webhook ingestion, Block Kit action listeners, SRE approval/rejection/snooze workflows,
shared SQLite database audit recording, and alert dispatching.
"""

import os
import sys
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Response
from pydantic import BaseModel

# Setup paths to import shared db and local modules
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared.db import get_connection
from slack_client import (
    slack_app,
    slack_handler,
    send_slack_alert,
    update_slack_message,
    verify_slack_signature,
    get_slack_config,
    is_live_configured,
)

load_dotenv()

# Setup logger
logger = logging.getLogger("shadow-it-detector.slack-bot")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# FastAPI application initialization
app = FastAPI(
    title="Shadow IT Detector - Slack & Approvals Service",
    description="SRE Slack Bot and Human-in-the-Loop Approval Management",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Database Helpers & Workflow Logic
# ---------------------------------------------------------------------------

def get_unnotified_high_risks() -> List[Dict[str, Any]]:
    """
    Fetches all HIGH-risk resources from the database that have not yet been notified
    (i.e., no existing record in the approvals table).
    Prevents duplicate Slack alerts across repeated pipeline scans.
    """
    query = """
        SELECT r.id, r.type, r.region, r.name, r.tags, r.owner_tag, 
               r.public_access, r.idle_days, r.est_monthly_cost, r.created_at,
               s.score, s.risk_bucket, s.explanation
        FROM resources r
        JOIN risk_scores s ON r.id = s.resource_id
        LEFT JOIN approvals a ON r.id = a.resource_id
        WHERE s.risk_bucket = 'HIGH' AND a.id IS NULL
    """
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]


def create_pending_approval(resource_id: str, slack_message_ts: Optional[str]) -> bool:
    """Inserts a new PENDING record into the approvals table."""
    insert_sql = """
        INSERT INTO approvals (
            resource_id, sre_name, status, action_taken, reason, slack_message_ts, decided_at
        ) VALUES (?, NULL, 'PENDING', NULL, NULL, ?, NULL)
    """
    try:
        with get_connection() as conn:
            conn.execute(insert_sql, (resource_id, slack_message_ts))
            logger.info(f"Created PENDING approval record for resource '{resource_id}' (ts={slack_message_ts})")
        return True
    except Exception as e:
        logger.error(f"Error creating pending approval for '{resource_id}': {e}")
        return False


def record_sre_decision(
    resource_id: str,
    action: str,
    sre_name: str,
    message_ts: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Updates or inserts the approval record for a resource when an SRE takes an action.
    
    Supported Actions:
      - 'approve' -> status: 'APPROVED', action_taken: 'approved — apply manually'
      - 'reject'  -> status: 'REJECTED', action_taken: 'flagged rogue resource'
      - 'snooze'  -> status: 'SNOOZED',  action_taken: 'snoozed alert for 24h'
    """
    action_clean = action.lower().strip()
    now_iso = datetime.now(timezone.utc).isoformat()

    if action_clean in ("approve", "approved"):
        status = "APPROVED"
        action_taken = "approved — apply manually"
    elif action_clean in ("reject", "rejected"):
        status = "REJECTED"
        action_taken = "flagged rogue resource"
    elif action_clean in ("snooze", "snoozed"):
        status = "SNOOZED"
        action_taken = "snoozed alert for 24h"
    else:
        status = action.upper()
        action_taken = f"action: {action}"

    with get_connection() as conn:
        # Check if record already exists
        existing = conn.execute(
            "SELECT id, status, sre_name, slack_message_ts FROM approvals WHERE resource_id = ? ORDER BY id DESC LIMIT 1",
            (resource_id,),
        ).fetchone()

        if existing:
            update_sql = """
                UPDATE approvals
                SET status = ?, sre_name = ?, action_taken = ?, reason = ?, decided_at = ?,
                    slack_message_ts = COALESCE(?, slack_message_ts)
                WHERE id = ?
            """
            conn.execute(
                update_sql,
                (status, sre_name, action_taken, reason, now_iso, message_ts, existing["id"]),
            )
            logger.info(
                f"Updated approval #{existing['id']} for '{resource_id}' -> status={status} by {sre_name}"
            )
        else:
            insert_sql = """
                INSERT INTO approvals (
                    resource_id, sre_name, status, action_taken, reason, slack_message_ts, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            conn.execute(
                insert_sql,
                (resource_id, sre_name, status, action_taken, reason, message_ts, now_iso),
            )
            logger.info(
                f"Inserted new approval for '{resource_id}' -> status={status} by {sre_name}"
            )

    return {
        "resource_id": resource_id,
        "status": status,
        "sre_name": sre_name,
        "action_taken": action_taken,
        "decided_at": now_iso,
        "reason": reason,
        "message_ts": message_ts,
    }


def process_high_risk_alerts() -> List[Dict[str, Any]]:
    """
    Core pipeline function: Identifies unnotified HIGH-risk findings, sends Slack alerts,
    and creates PENDING approval records in the shared database.
    """
    logger.info("Checking database for unnotified HIGH-risk resources...")
    high_risks = get_unnotified_high_risks()
    
    if not high_risks:
        logger.info("No new unnotified HIGH-risk findings found.")
        return []

    logger.info(f"Found {len(high_risks)} unnotified HIGH-risk finding(s) to alert.")
    dispatched = []

    for item in high_risks:
        res_id = item["id"]
        risk_info = {
            "score": item["score"],
            "risk_bucket": item["risk_bucket"],
            "explanation": item.get("explanation"),
        }
        
        success, msg_ts = send_slack_alert(
            resource=item,
            risk=risk_info,
            explanation=item.get("explanation"),
        )
        
        if success:
            create_pending_approval(resource_id=res_id, slack_message_ts=msg_ts)
            dispatched.append({
                "resource_id": res_id,
                "slack_message_ts": msg_ts,
                "score": item["score"],
                "status": "PENDING",
            })
        else:
            logger.error(f"Failed to deliver Slack alert for resource '{res_id}'.")

    logger.info(f"Dispatched {len(dispatched)} Slack alert(s).")
    return dispatched


def simulate_finding(
    resource_id: str = "sim-i-0987654321fedcba",
    resource_type: str = "EC2",
    resource_name: str = "Demo-Rogue-Elasticsearch",
    score: float = 88.5,
    explanation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates a simulated HIGH-risk finding and delivers a demo alert to Slack.
    Does NOT modify AWS or mutate live infrastructure.
    """
    if not explanation:
        explanation = (
            "Resource has public IP with open Elasticsearch port 9200, is missing mandatory owner tag, "
            "and has been idle for 45 days generating unnecessary cloud costs. Recommended remediation is immediate quarantine."
        )

    sim_resource = {
        "id": resource_id,
        "type": resource_type,
        "name": resource_name,
        "region": "us-east-1",
        "public_access": True,
        "idle_days": 45,
        "est_monthly_cost": 184.50,
        "tags": '{"environment": "sandbox", "team": "data"}',
    }

    sim_risk = {
        "score": score,
        "risk_bucket": "HIGH",
        "explanation": explanation,
    }

    # Ensure resource exists in shared resources / risk_scores table if not present
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO resources (
                    id, type, region, name, tags, owner_tag, public_access, idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    resource_id, resource_type, "us-east-1", resource_name,
                    sim_resource["tags"], None, 1, 45, 184.50, now_iso, now_iso
                )
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO risk_scores (
                    resource_id, score, risk_bucket, model_version, explanation, scored_at
                ) VALUES (?, ?, 'HIGH', 'rf-v1', ?, ?)
                """,
                (resource_id, score, explanation, now_iso)
            )
    except Exception as e:
        logger.warning(f"Note: Could not insert simulated resource to DB: {e}")

    success, msg_ts = send_slack_alert(
        resource=sim_resource,
        risk=sim_risk,
        explanation=explanation,
        is_simulation=True,
    )

    if success:
        create_pending_approval(resource_id=resource_id, slack_message_ts=msg_ts)

    return {
        "simulation": True,
        "resource_id": resource_id,
        "slack_message_ts": msg_ts,
        "score": score,
        "success": success,
    }


def handle_slack_action_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses and processes an interactive action payload from Slack.
    Works for both Slack Bolt events and direct webhook payloads.
    """
    actions = payload.get("actions", [])
    if not actions:
        raise ValueError("No actions found in Slack payload.")

    action_data = actions[0]
    action_id = action_data.get("action_id", "").lower()
    resource_id = action_data.get("value")

    if not resource_id:
        raise ValueError("No resource_id (action value) provided in Slack action.")

    user = payload.get("user", {})
    user_id = user.get("id", "U_UNKNOWN")
    username = user.get("username") or user.get("name") or user_id

    container = payload.get("container", {})
    channel_id = (
        payload.get("channel", {}).get("id")
        or container.get("channel_id")
        or get_slack_config()["channel"]
    )
    message_ts = payload.get("message", {}).get("ts") or container.get("message_ts")

    # Save to database
    decision = record_sre_decision(
        resource_id=resource_id,
        action=action_id,
        sre_name=username,
        message_ts=message_ts,
    )

    # Update Slack message
    if message_ts and channel_id:
        update_slack_message(
            channel_id=channel_id,
            message_ts=message_ts,
            resource_id=resource_id,
            status=decision["status"],
            sre_name=username,
            action_taken=decision["action_taken"],
            decided_at=decision["decided_at"],
            reason=decision.get("reason"),
        )

    return decision


# ---------------------------------------------------------------------------
# Slack Bolt Action Handlers
# ---------------------------------------------------------------------------

if slack_app:
    @slack_app.action("approve")
    def bolt_handle_approve(ack, body, client):
        ack()
        try:
            handle_slack_action_payload(body)
        except Exception as e:
            logger.error(f"Error handling Slack approve action: {e}")

    @slack_app.action("reject")
    def bolt_handle_reject(ack, body, client):
        ack()
        try:
            handle_slack_action_payload(body)
        except Exception as e:
            logger.error(f"Error handling Slack reject action: {e}")

    @slack_app.action("snooze")
    def bolt_handle_snooze(ack, body, client):
        ack()
        try:
            handle_slack_action_payload(body)
        except Exception as e:
            logger.error(f"Error handling Slack snooze action: {e}")


# ---------------------------------------------------------------------------
# FastAPI Endpoints
# ---------------------------------------------------------------------------

class SimulateRequest(BaseModel):
    resource_id: Optional[str] = "sim-ec2-rogue-01"
    resource_type: Optional[str] = "EC2"
    resource_name: Optional[str] = "Demo-Shadow-Server"
    score: Optional[float] = 88.5
    explanation: Optional[str] = None


@app.get("/health")
def health_check():
    """Health check endpoint displaying service mode and configuration status."""
    cfg = get_slack_config()
    is_live = is_live_configured()
    
    # Test DB connection
    db_ok = False
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
            db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "healthy",
        "service": "shadow-it-detector-slack-bot",
        "mode": "LIVE" if is_live else "MOCK / SIMULATION",
        "database_connected": db_ok,
        "slack_channel": cfg["channel"],
    }


@app.post("/slack/events")
async def slack_events_endpoint(request: Request):
    """
    Primary Slack webhook endpoint for Bolt events and interactive actions.
    Dispatches to Bolt SlackRequestHandler when running in LIVE mode.
    """
    if slack_handler:
        return await slack_handler.handle(request)
    
    # Handle mock / fallback webhook directly
    raw_body = await request.body()
    content_type = request.headers.get("content-type", "")

    payload = {}
    if "application/x-www-form-urlencoded" in content_type:
        from urllib.parse import parse_qs
        form_data = parse_qs(raw_body.decode("utf-8"))
        if "payload" in form_data:
            payload = json.loads(form_data["payload"][0])
    elif "application/json" in content_type:
        payload = json.loads(raw_body.decode("utf-8"))

    if payload:
        try:
            decision = handle_slack_action_payload(payload)
            return {"status": "ok", "decision": decision}
        except Exception as e:
            logger.error(f"Error processing direct Slack action: {e}")
            raise HTTPException(status_code=400, detail=str(e))

    return {"status": "mock_ack"}


@app.post("/slack/interactive")
async def slack_interactive_endpoint(request: Request):
    """
    Dedicated endpoint for Slack interactive payloads with explicit signature verification.
    """
    raw_body = await request.body()
    cfg = get_slack_config()

    # If live mode, verify signature
    if is_live_configured():
        ts = request.headers.get("x-slack-request-timestamp")
        sig = request.headers.get("x-slack-signature")
        if not verify_slack_signature(cfg["signing_secret"], raw_body, ts, sig):
            raise HTTPException(status_code=401, detail="Invalid Slack signature or expired timestamp.")

    content_type = request.headers.get("content-type", "")
    payload = {}
    if "application/x-www-form-urlencoded" in content_type:
        from urllib.parse import parse_qs
        form_data = parse_qs(raw_body.decode("utf-8"))
        if "payload" in form_data:
            payload = json.loads(form_data["payload"][0])
    elif "application/json" in content_type:
        payload = json.loads(raw_body.decode("utf-8"))

    if not payload:
        raise HTTPException(status_code=400, detail="Missing or invalid payload.")

    try:
        decision = handle_slack_action_payload(payload)
        return {"status": "ok", "decision": decision}
    except Exception as e:
        logger.error(f"Error processing interactive action: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/send-alerts")
def trigger_alert_dispatch():
    """Triggers the alert dispatching process for unnotified HIGH-risk findings."""
    dispatched = process_high_risk_alerts()
    return {
        "status": "success",
        "count": len(dispatched),
        "dispatched": dispatched,
    }


@app.post("/simulate-alert")
def trigger_simulated_alert(req: SimulateRequest):
    """
    Triggers a safe simulated HIGH-risk finding alert for demo or viva presentations.
    Does not touch real AWS infrastructure.
    """
    result = simulate_finding(
        resource_id=req.resource_id or "sim-ec2-rogue-01",
        resource_type=req.resource_type or "EC2",
        resource_name=req.resource_name or "Demo-Shadow-Server",
        score=req.score or 88.5,
        explanation=req.explanation,
    )
    return result


@app.get("/approvals")
def list_approvals():
    """Lists all approval audit records from the shared database."""
    query = """
        SELECT a.id, a.resource_id, a.sre_name, a.status, a.action_taken, 
               a.reason, a.slack_message_ts, a.decided_at,
               r.type, r.name, r.est_monthly_cost
        FROM approvals a
        LEFT JOIN resources r ON a.resource_id = r.id
        ORDER BY a.id DESC
    """
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
        return {"approvals": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# CLI Execution
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for running the bot or processing alerts."""
    args = sys.argv[1:]
    
    print("=" * 60)
    print("SHADOW IT DETECTOR: SLACK BOT & APPROVAL SERVICE")
    print("=" * 60)
    
    if "--simulate" in args:
        print("[*] Running in SIMULATION mode (triggering demo high-risk alert)...")
        res = simulate_finding()
        print(f"Simulation Result: {json.dumps(res, indent=2)}")
    elif "--server" in args:
        import uvicorn
        port = int(os.getenv("PORT", "8000"))
        print(f"[*] Starting FastAPI Slack server on port {port}...")
        uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
    else:
        print("[*] Checking database for HIGH-risk findings to dispatch...")
        dispatched = process_high_risk_alerts()
        print(f"Dispatched {len(dispatched)} alert(s).")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
