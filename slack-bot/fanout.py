"""
Incident Fan-Out & Pipeline Orchestrator.
Dispatches detected rogue findings across:
1. Database Incident Creation (with deduplication)
2. Runbook Generation (LLM or template fallback)
3. GitHub Repository Publishing (via Contents API)
4. Slack Action Request (Block Kit with Approve/Reject/Snooze)
5. Live Feed SSE event streaming
"""

import os
import sys
import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("shadow-it.fanout")

REPO_ROOT = Path(__file__).resolve().parent.parent
LLM_DIR = REPO_ROOT / "llm-explainability"
SLACK_BOT_DIR = REPO_ROOT / "slack-bot"

for p in (REPO_ROOT, LLM_DIR, SLACK_BOT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from shared.db import get_connection
from runbook_generator import generate_runbook_with_llm_or_fallback
from github_client import push_runbook_to_github
from slack_client import send_slack_alert, is_live_configured

# In-memory SSE event bus for real-time live feed updates
_live_event_listeners = []

def register_event_listener(queue):
    _live_event_listeners.append(queue)

def unregister_event_listener(queue):
    if queue in _live_event_listeners:
        _live_event_listeners.remove(queue)

def emit_live_event(event_type: str, data: Dict[str, Any]):
    """Dispatches a real-time event to all connected SSE clients."""
    payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    for q in list(_live_event_listeners):
        try:
            q.put_nowait(payload)
        except Exception:
            pass

def compute_dedupe_key(account: str, region: str, resource_id: str, trigger_source: str = "default") -> str:
    raw = f"{account}:{region}:{resource_id}:{trigger_source}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def handle_new_incident(
    resource: Dict[str, Any],
    risk: Dict[str, Any],
    trigger_source: str = "Shadow IT Risk Breach",
    account_id: str = "1234****9012"
) -> Dict[str, Any]:
    """
    Idempotent automated fan-out pipeline for flagged rogue cloud resources.
    Executes: Incident Record -> Runbook -> GitHub -> Slack -> SSE Notification.
    """
    res_id = str(resource.get("id"))
    res_type = str(resource.get("type", "EC2")).upper()
    region = str(resource.get("region", "us-east-1"))
    score = float(risk.get("score", 0.0))
    risk_tier = str(risk.get("risk_bucket", "HIGH"))
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    dashboard_base = os.getenv("DASHBOARD_BASE_URL", "http://localhost:7860")

    dedupe_key = compute_dedupe_key(account_id, region, res_id, trigger_source)

    with get_connection() as conn:
        existing = conn.execute("""
            SELECT * FROM incidents WHERE dedupe_key = ? AND status NOT IN ('Resolved', 'Rejected')
        """, (dedupe_key,)).fetchone()

        if existing:
            inc_id = existing["id"]
            logger.info(f"Deduplication matched: Incident {inc_id} already open for {res_id}. Updating severity.")
            if score > (existing["score"] or 0):
                conn.execute("""
                    UPDATE incidents SET score = ?, risk_tier = ?, updated_at = ? WHERE id = ?
                """, (score, risk_tier, now_iso, inc_id))
            return dict(existing)

        # Ensure resource exists in resources table to satisfy foreign key
        conn.execute("""
            INSERT OR IGNORE INTO resources (
                id, type, region, name, tags, owner_tag, public_access,
                idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (
            res_id, res_type, region, resource.get("name", res_id),
            resource.get("tags", "{}"), resource.get("owner_tag", ""),
            resource.get("public_access", 0), resource.get("idle_days", 0),
            resource.get("est_monthly_cost", 0.0), now_iso, now_iso
        ))

        # 1. Create new Incident row
        inc_id = f"INC-{int(now.timestamp() * 1000) % 900000 + 100000}"
        pipeline_status = {
            "detected": "ok",
            "runbook": "pending",
            "github": "pending",
            "slack": "pending",
        }
        conn.execute("""
            INSERT INTO incidents (
                id, resource_id, type, region, account_id, trigger_source, score, risk_tier,
                dedupe_key, status, pipeline_status, detected_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?)
        """, (
            inc_id, res_id, res_type, region, account_id, trigger_source, score, risk_tier,
            dedupe_key, json.dumps(pipeline_status), now_iso, now_iso
        ))

    emit_live_event("incident_created", {
        "incident_id": inc_id,
        "resource_id": res_id,
        "type": res_type,
        "region": region,
        "score": score,
        "tier": risk_tier,
        "status": "Open",
        "description": f"New rogue {res_type} incident created: {res_id}"
    })

    # 2. Generate Incident Runbook
    runbook_md, generator = generate_runbook_with_llm_or_fallback(
        incident_id=inc_id,
        resource=resource,
        risk_score=score,
        risk_tier=risk_tier,
        trigger_source=trigger_source,
        account_id=account_id,
        region=region
    )
    pipeline_status["runbook"] = "ok"

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO incident_runbooks (
                incident_id, markdown, version, generator, github_url, created_at
            ) VALUES (?, ?, 1, ?, NULL, ?)
        """, (inc_id, runbook_md, generator, now_iso))
        
        conn.execute("""
            UPDATE incidents SET pipeline_status = ?, updated_at = ? WHERE id = ?
        """, (json.dumps(pipeline_status), now_iso, inc_id))

    emit_live_event("runbook_generated", {
        "incident_id": inc_id,
        "resource_id": res_id,
        "generator": generator,
        "description": f"Incident runbook generated ({generator})"
    })

    # 3. Push Runbook to GitHub
    gh_result = push_runbook_to_github(
        incident_id=inc_id,
        resource_id=res_id,
        markdown_content=runbook_md
    )
    gh_url = gh_result.get("html_url")
    pipeline_status["github"] = gh_result.get("status", "failed")

    with get_connection() as conn:
        if gh_url:
            conn.execute("""
                UPDATE incident_runbooks SET github_url = ? WHERE incident_id = ?
            """, (gh_url, inc_id))
        conn.execute("""
            UPDATE incidents SET pipeline_status = ?, updated_at = ? WHERE id = ?
        """, (json.dumps(pipeline_status), now_iso, inc_id))

    emit_live_event("github_pushed", {
        "incident_id": inc_id,
        "resource_id": res_id,
        "github_status": pipeline_status["github"],
        "github_url": gh_url,
        "description": "Runbook pushed to GitHub" if gh_url else "GitHub runbook push skipped/mock"
    })

    # 4. Dispatch Slack Action Request
    incident_url = f"{dashboard_base}/#incident-{inc_id}"
    success, msg_ts = send_slack_alert(
        resource=resource,
        risk=risk,
        explanation=resource.get("explanation") or risk.get("explanation"),
        dashboard_url=incident_url,
        github_runbook_url=gh_url,
        incident_id=inc_id
    )

    pipeline_status["slack"] = "ok" if success else "failed"

    with get_connection() as conn:
        if success:
            conn.execute("""
                INSERT INTO approvals (
                    resource_id, sre_name, status, action_taken, reason, slack_message_ts, decided_at
                ) VALUES (?, NULL, 'PENDING', NULL, NULL, ?, NULL)
            """, (res_id, msg_ts))
            
            # Update incident status to 'Pending Approval'
            conn.execute("""
                UPDATE incidents SET status = 'Pending Approval', pipeline_status = ?, updated_at = ? WHERE id = ?
            """, (json.dumps(pipeline_status), now_iso, inc_id))
        else:
            conn.execute("""
                UPDATE incidents SET pipeline_status = ?, updated_at = ? WHERE id = ?
            """, (json.dumps(pipeline_status), now_iso, inc_id))

    emit_live_event("slack_sent", {
        "incident_id": inc_id,
        "resource_id": res_id,
        "slack_status": pipeline_status["slack"],
        "message_ts": msg_ts,
        "description": "Slack interactive approval request sent" if success else "Slack notification failed"
    })

    return {
        "id": inc_id,
        "resource_id": res_id,
        "type": res_type,
        "region": region,
        "score": score,
        "risk_tier": risk_tier,
        "status": "Pending Approval" if success else "Open",
        "pipeline_status": pipeline_status,
        "github_url": gh_url,
        "slack_message_ts": msg_ts
    }
