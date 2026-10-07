"""
FastAPI Server for Shadow.Guard - Cloud Risk Scoring & Rogue Cloud Resource Detector.
Provides RESTful APIs and SSE streams for:
- Live Feed (Server-Sent Events) and Account-Wide Telemetry
- Incidents Matrix & GenAI Incident Runbooks
- SRE Approvals & Workflow Management (Reminders, Comments, Slack Sync)
- In-Memory Log Analyzer (Strictly Zero-Persistence)
- Slack Interactivity Webhook (/slack/interactions) with HMAC-SHA256 verification
- Background Multi-Region Read-Only AWS Telemetry Collector
"""

import os
import sys
import json
import time
import hmac
import hashlib
import asyncio
import logging
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request, Response, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

# Ensure repository root, llm-explainability, and slack-bot are on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LLM_DIR = REPO_ROOT / "llm-explainability"
SLACK_BOT_DIR = REPO_ROOT / "slack-bot"

for p in (REPO_ROOT, LLM_DIR, SLACK_BOT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from shared.db import get_connection, DB_PATH
from shared.log_parser import parse_log_content, generate_log_incident_report
from detection.aws_collector import collect_account_wide_inventory, is_mock_mode
from runbook_generator import generate_runbook_with_llm_or_fallback
from github_client import push_runbook_to_github
from slack_client import (
    get_slack_config,
    is_live_configured,
    verify_slack_signature,
    update_slack_message,
)
import importlib.util
_spec = importlib.util.spec_from_file_location("slack_bot_main", str(SLACK_BOT_DIR / "app.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
handle_slack_action_payload = _mod.handle_slack_action_payload
from fanout import (
    handle_new_incident,
    register_event_listener,
    unregister_event_listener,
    emit_live_event,
)

logger = logging.getLogger("shadow-it.server")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s]: %(message)s")

# ---------------------------------------------------------------------------
# Background Telemetry Scanner & Event Generator
# ---------------------------------------------------------------------------
_scan_lock = threading.Lock()
_stop_scanner_event = threading.Event()
_recent_events_cache: List[Dict[str, Any]] = []

def record_live_event(event_type: str, data: Dict[str, Any]):
    evt = {
        "id": f"evt-{int(time.time() * 1000)}",
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    _recent_events_cache.insert(0, evt)
    if len(_recent_events_cache) > 200:
        _recent_events_cache.pop()
    emit_live_event(event_type, data)

def background_telemetry_loop():
    """Background worker collecting AWS inventory and dispatching rogue findings."""
    interval = int(os.getenv("SCAN_INTERVAL_SECONDS", "300"))
    logger.info(f"Background Telemetry Worker started (Cadence: {interval}s, Mock Mode: {is_mock_mode()})")

    # Initial delay before first full scan to let server bind
    time.sleep(2)

    while not _stop_scanner_event.is_set():
        if _scan_lock.acquire(blocking=False):
            try:
                logger.info("Executing periodic account-wide cloud scan...")
                inv = collect_account_wide_inventory()
                
                # Check for flagged resources without open incidents
                for res in inv.get("resources", []):
                    if res.get("is_flagged"):
                        # Get risk score
                        with get_connection() as conn:
                            score_row = conn.execute(
                                "SELECT score, risk_bucket FROM risk_scores WHERE resource_id = ?",
                                (res["id"],)
                            ).fetchone()
                            
                            score = float(score_row["score"]) if score_row else 75.0
                            bucket = score_row["risk_bucket"] if score_row else "HIGH"

                        risk_data = {"score": score, "risk_bucket": bucket}
                        handle_new_incident(
                            resource=res,
                            risk=risk_data,
                            trigger_source="Automated Periodic Multi-Region Scan",
                            account_id=inv.get("account_id", "1234****9012")
                        )

                record_live_event("scan_completed", {
                    "account_id": inv.get("account_id"),
                    "total_resources": inv.get("total_resources"),
                    "flagged_resources": inv.get("flagged_resources"),
                    "regions_scanned": inv.get("regions_scanned"),
                    "scan_duration_sec": inv.get("scan_duration_sec"),
                    "description": f"Multi-region sweep finished ({inv.get('total_resources')} assets scanned)"
                })
            except Exception as e:
                logger.error(f"Error in background telemetry scan: {e}")
            finally:
                _scan_lock.release()

        # In mock mode, periodically emit lightweight demo events so feed visibly moves
        sleep_elapsed = 0
        demo_cadence = 6 if is_mock_mode() else 60
        while sleep_elapsed < interval and not _stop_scanner_event.is_set():
            time.sleep(demo_cadence)
            sleep_elapsed += demo_cadence
            if is_mock_mode() and not _stop_scanner_event.is_set():
                # Emit subtle mock telemetry tick
                now_iso = datetime.now(timezone.utc).isoformat()
                mock_events = [
                    ("cloudwatch_heartbeat", {"service": "CloudWatch", "metric": "CPUUtilization", "regions": ["us-east-1", "us-west-2"], "description": "CloudWatch telemetry batch query refreshed"}),
                    ("compliance_check", {"policy": "CIS-Benchmark-2.1", "evaluated_rules": 14, "status": "Compliant", "description": "Continuous compliance rule probe verified"}),
                    ("cost_explorer_sync", {"mtd_spend": 384.50, "currency": "USD", "description": "Cost Explorer daily budget threshold within limits"}),
                ]
                import random
                chosen_ev, chosen_data = random.choice(mock_events)
                record_live_event(chosen_ev, chosen_data)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure DB and start background worker
    with get_connection() as conn:
        pass  # triggers ensure_db_initialized
    
    scanner_thread = threading.Thread(target=background_telemetry_loop, daemon=True)
    scanner_thread.start()

    # Self-check logger for enabled integrations
    slack_live = is_live_configured()
    gh_configured = bool(os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_RUNBOOK_REPO"))
    llm_configured = bool(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"))
    logger.info("=" * 60)
    logger.info("SHADOW.GUARD SYSTEM STARTUP AUDIT")
    logger.info(f"[*] Telemetry Mode : {'MOCK / DEMO' if is_mock_mode() else 'LIVE AWS'}")
    logger.info(f"[*] Slack Bot      : {'LIVE CONNECTED' if slack_live else 'MOCK / SIMULATION'}")
    logger.info(f"[*] GitHub Runbooks: {'CONFIGURED' if gh_configured else 'OFFLINE / MOCK'}")
    logger.info(f"[*] LLM Explainer  : {'ENABLED' if llm_configured else 'DETERMINISTIC TEMPLATE'}")
    logger.info("=" * 60)

    yield

    # Shutdown
    _stop_scanner_event.set()

app = FastAPI(
    title="Shadow IT Risk Detector & Cloud Governance Hub",
    description="Enterprise API backend for rogue cloud asset detection, ML risk scoring, and SRE approvals.",
    version="3.0.0",
    lifespan=lifespan,
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class WorkflowStatusUpdate(BaseModel):
    status: str = Field(..., description="'Pending', 'In Review', 'Snoozed', or 'Escalated'")
    reviewer: Optional[str] = Field(default="sre.engineer")
    reason: Optional[str] = None

class CreateReminderRequest(BaseModel):
    scheduled_time: str
    note: Optional[str] = "Follow up on rogue asset"
    post_to_slack: bool = False

class CreateCommentRequest(BaseModel):
    author_name: str = Field(default="sre.operator")
    comment_text: str = Field(..., min_length=1)
    post_to_slack: bool = False

# ---------------------------------------------------------------------------
# API Routes: Dashboard & Live Feed Telemetry (Tasks 1, 2 & Addendum A1)
# ---------------------------------------------------------------------------
@app.get("/api/dashboard/stats")
def get_dashboard_stats(region: Optional[str] = Query(None, description="Optional region filter")):
    """Returns high-level KPI cards and aggregated charts data across the AWS account."""
    with get_connection() as conn:
        region_clause = ""
        params = []
        if region and region.lower() != "all":
            region_clause = " WHERE region = ?"
            params.append(region)

        # Total and flagged count
        if region_clause:
            total_res = conn.execute(f"SELECT COUNT(*) FROM resources{region_clause}", params).fetchone()[0]
            flagged_res = conn.execute(f"SELECT COUNT(*) FROM resources{region_clause} AND is_flagged = 1", params).fetchone()[0]
        else:
            total_res = conn.execute("SELECT COUNT(*) FROM resources").fetchone()[0]
            flagged_res = conn.execute("SELECT COUNT(*) FROM resources WHERE is_flagged = 1").fetchone()[0]

        # Risk buckets count
        bucket_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        q_buckets = f"""
            SELECT s.risk_bucket, COUNT(*) as cnt
            FROM risk_scores s
            JOIN resources r ON s.resource_id = r.id
            {region_clause}
            GROUP BY s.risk_bucket
        """
        rows = conn.execute(q_buckets, params).fetchall()
        for r in rows:
            bucket_counts[r["risk_bucket"]] = r["cnt"]

        # Safe count (unflagged compliant resources)
        q_safe = f"SELECT COUNT(*) FROM resources WHERE is_flagged = 0 {'AND region = ?' if region_clause else ''}"
        safe_count = conn.execute(q_safe, params if region_clause else []).fetchone()[0]
        bucket_counts["SAFE"] = safe_count

        # Total wasted monthly spend (from flagged resources)
        q_cost = f"SELECT COALESCE(SUM(est_monthly_cost), 0.0) as total_wasted FROM resources WHERE is_flagged = 1 {'AND region = ?' if region_clause else ''}"
        wasted_cost_row = conn.execute(q_cost, params if region_clause else []).fetchone()
        wasted_monthly_cost = round(float(wasted_cost_row["total_wasted"]), 2)

        # Pending SRE Approvals
        pending_approvals = conn.execute("""
            SELECT COUNT(*) FROM approvals WHERE status = 'PENDING' OR status = 'Pending Approval'
        """).fetchone()[0]

        # Breakdown by resource service type (EC2, S3, RDS, etc.)
        q_type = f"""
            SELECT type, COUNT(*) as count, COALESCE(SUM(est_monthly_cost), 0) as total_cost,
                   SUM(CASE WHEN is_flagged = 1 THEN 1 ELSE 0 END) as flagged_count
            FROM resources
            {region_clause}
            GROUP BY type
        """
        by_type_rows = conn.execute(q_type, params).fetchall()
        by_type = [dict(r) for r in by_type_rows]

        # Spend by Region
        by_reg_rows = conn.execute("""
            SELECT region, COUNT(*) as count, COALESCE(SUM(est_monthly_cost), 0) as total_cost,
                   SUM(CASE WHEN is_flagged = 1 THEN 1 ELSE 0 END) as flagged_count
            FROM resources
            GROUP BY region
        """).fetchall()
        by_region = [dict(r) for r in by_reg_rows]

        # Latest scan snapshot
        snap = conn.execute("SELECT * FROM account_snapshots ORDER BY id DESC LIMIT 1").fetchone()
        snapshot_meta = {}
        if snap:
            try:
                snapshot_meta = json.loads(snap["metrics_json"])
            except Exception:
                pass

        all_regions_rows = conn.execute("SELECT DISTINCT region FROM resources WHERE region IS NOT NULL").fetchall()
        available_regions = [r[0] for r in all_regions_rows]

    return {
        "account_id": snapshot_meta.get("account_id", "1234****9012"),
        "is_mock": is_mock_mode(),
        "total_resources": total_res,
        "flagged_resources": flagged_res,
        "compliance_rate": round(((total_res - flagged_res) / total_res * 100), 1) if total_res > 0 else 100.0,
        "risk_buckets": bucket_counts,
        "wasted_monthly_cost": wasted_monthly_cost,
        "pending_approvals": pending_approvals,
        "by_type": by_type,
        "by_region": by_region,
        "available_regions": available_regions,
        "regions_scanned": snapshot_meta.get("regions_scanned", ["us-east-1", "us-west-2", "eu-west-1"]),
        "regions_failed": snapshot_meta.get("regions_failed", []),
        "scan_duration_sec": snapshot_meta.get("scan_duration_sec", 0.5),
        "last_scan_time": snap["timestamp"] if snap else datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/live-feed")
def get_live_feed_recent():
    """Polling fallback endpoint returning the recent event stream items."""
    # Ensure initial feed has elements from DB if empty
    if not _recent_events_cache:
        with get_connection() as conn:
            inc_rows = conn.execute("SELECT * FROM incidents ORDER BY detected_at DESC LIMIT 15").fetchall()
            for r in inc_rows:
                _recent_events_cache.append({
                    "id": f"evt-init-{r['id']}",
                    "event": "incident_created",
                    "timestamp": r["detected_at"],
                    "data": {
                        "incident_id": r["id"],
                        "resource_id": r["resource_id"],
                        "type": r["type"],
                        "region": r["region"],
                        "score": r["score"],
                        "tier": r["risk_tier"],
                        "status": r["status"],
                        "description": f"Flagged rogue {r['type']} asset: {r['resource_id']}"
                    }
                })

    return {
        "count": len(_recent_events_cache),
        "events": _recent_events_cache[:60]
    }

@app.get("/api/live-feed/stream")
async def stream_live_feed(request: Request):
    """
    Server-Sent Events (SSE) streaming endpoint for real-time telemetry.
    Pushes events as they occur in memory or during scans.
    """
    queue = asyncio.Queue()
    register_event_listener(queue)

    async def event_generator():
        # First send historical backlog
        for item in _recent_events_cache[:10]:
            yield f"data: {json.dumps(item)}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event_data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event_data)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment
                    yield ": keepalive\n\n"
        finally:
            unregister_event_listener(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )

# ---------------------------------------------------------------------------
# API Routes: Incidents Tab & Runbooks (Task 3 & Addendum A2, A4)
# ---------------------------------------------------------------------------
@app.get("/api/incidents")
def list_incidents(
    search: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    risk_tier: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    """Lists all previous and open incidents enriched with status and runbook metadata."""
    query = """
        SELECT i.*, r.name as resource_name, r.est_monthly_cost, r.idle_days,
               r.public_access, b.github_url, b.generator as runbook_generator,
               a.status as approval_status, a.sre_name as reviewer_name, a.decided_at
        FROM incidents i
        LEFT JOIN resources r ON i.resource_id = r.id
        LEFT JOIN incident_runbooks b ON i.id = b.incident_id
        LEFT JOIN (
            SELECT a1.* FROM approvals a1
            INNER JOIN (
                SELECT resource_id, MAX(id) as max_id FROM approvals GROUP BY resource_id
            ) a2 ON a1.id = a2.max_id
        ) a ON i.resource_id = a.resource_id
        WHERE 1=1
    """
    params = []

    if search:
        query += " AND (i.id LIKE ? OR i.resource_id LIKE ? OR r.name LIKE ?)"
        s = f"%{search.strip()}%"
        params.extend([s, s, s])

    if service:
        query += " AND UPPER(i.type) = ?"
        params.append(service.upper().strip())

    if risk_tier:
        query += " AND UPPER(i.risk_tier) = ?"
        params.append(risk_tier.upper().strip())

    if status:
        query += " AND UPPER(i.status) = ?"
        params.append(status.upper().strip())

    if region and region.lower() != "all":
        query += " AND i.region = ?"
        params.append(region.strip())

    query += " ORDER BY i.detected_at DESC"

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            # Parse pipeline status
            pip_st = {"detected": "ok", "runbook": "ok", "github": "ok", "slack": "ok"}
            if item.get("pipeline_status"):
                try:
                    pip_st = json.loads(item["pipeline_status"])
                except Exception:
                    pass
            item["pipeline_status"] = pip_st
            result.append(item)

        return {"count": len(result), "incidents": result}

@app.get("/api/incidents/{incident_id}/report")
def get_incident_report(incident_id: str):
    """
    Returns the LLM-generated incident runbook for an incident.
    Generates lazily on first access if not yet created and caches in DB.
    """
    with get_connection() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

        # Check existing cached runbook
        runbook_row = conn.execute(
            "SELECT * FROM incident_runbooks WHERE incident_id = ? ORDER BY version DESC LIMIT 1",
            (incident_id,)
        ).fetchone()

        if runbook_row:
            return {
                "incident_id": incident_id,
                "markdown": runbook_row["markdown"],
                "version": runbook_row["version"],
                "generator": runbook_row["generator"],
                "github_url": runbook_row["github_url"],
                "created_at": runbook_row["created_at"],
                "cached": True
            }

        # Lazy generation
        res_row = conn.execute("SELECT * FROM resources WHERE id = ?", (inc["resource_id"],)).fetchone()
        res_dict = dict(res_row) if res_row else {"id": inc["resource_id"], "type": inc["type"]}

        runbook_md, generator = generate_runbook_with_llm_or_fallback(
            incident_id=incident_id,
            resource=res_dict,
            risk_score=inc["score"] or 75.0,
            risk_tier=inc["risk_tier"] or "HIGH",
            trigger_source=inc["trigger_source"] or "Manual Review",
            account_id=inc["account_id"] or "1234****9012",
            region=inc["region"] or "us-east-1"
        )

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO incident_runbooks (incident_id, markdown, version, generator, github_url, created_at)
            VALUES (?, ?, 1, ?, NULL, ?)
        """, (incident_id, runbook_md, generator, now_iso))

        return {
            "incident_id": incident_id,
            "markdown": runbook_md,
            "version": 1,
            "generator": generator,
            "github_url": None,
            "created_at": now_iso,
            "cached": False
        }

@app.post("/api/incidents/{incident_id}/regenerate")
def regenerate_incident_runbook(incident_id: str):
    """Regenerates the incident runbook (bump version N+1) and updates GitHub if configured."""
    with get_connection() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        latest_rb = conn.execute(
            "SELECT MAX(version) as max_v FROM incident_runbooks WHERE incident_id = ?",
            (incident_id,)
        ).fetchone()
        next_ver = (latest_rb["max_v"] or 1) + 1

        res_row = conn.execute("SELECT * FROM resources WHERE id = ?", (inc["resource_id"],)).fetchone()
        res_dict = dict(res_row) if res_row else {"id": inc["resource_id"], "type": inc["type"]}

        runbook_md, generator = generate_runbook_with_llm_or_fallback(
            incident_id=incident_id,
            resource=res_dict,
            risk_score=inc["score"] or 75.0,
            risk_tier=inc["risk_tier"] or "HIGH",
            trigger_source=inc["trigger_source"] or "Manual Regeneration",
            account_id=inc["account_id"] or "1234****9012",
            region=inc["region"] or "us-east-1"
        )

        # Update on GitHub
        gh_res = push_runbook_to_github(
            incident_id=incident_id,
            resource_id=inc["resource_id"],
            markdown_content=runbook_md
        )
        gh_url = gh_res.get("html_url")

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO incident_runbooks (incident_id, markdown, version, generator, github_url, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (incident_id, runbook_md, next_ver, generator, gh_url, now_iso))

    record_live_event("runbook_regenerated", {
        "incident_id": incident_id,
        "version": next_ver,
        "generator": generator,
        "github_url": gh_url,
        "description": f"Incident {incident_id} runbook regenerated (v{next_ver})"
    })

    return {
        "status": "success",
        "incident_id": incident_id,
        "version": next_ver,
        "generator": generator,
        "github_url": gh_url,
        "markdown": runbook_md
    }

# ---------------------------------------------------------------------------
# API Routes: Log Analyzer (Task 4 - Strictly Zero-Persistence)
# ---------------------------------------------------------------------------
@app.post("/api/log-analyzer")
async def analyze_uploaded_log(file: UploadFile = File(...)):
    """
    Parses and analyzes uploaded log file (.txt or .log) strictly in-memory.
    Zero-persistence guarantee: No disk writes, no DB writes, no external pushing.
    """
    filename = file.filename or "unknown.log"
    ext = Path(filename).suffix.lower()
    if ext not in (".txt", ".log"):
        raise HTTPException(status_code=400, detail="Only .txt and .log file formats are supported.")

    content_bytes = await file.read()
    max_size = 5 * 1024 * 1024  # 5 MB
    if len(content_bytes) > max_size:
        raise HTTPException(status_code=400, detail="Uploaded file exceeds maximum permitted size of 5 MB.")

    try:
        content_str = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode log file content: {e}")

    # Parse in-memory metrics
    metrics = parse_log_content(content_str)

    # Generate incident report in-memory
    report_markdown = generate_log_incident_report(metrics, content_str)

    # Return pure in-memory response
    return {
        "filename": filename,
        "file_size_bytes": len(content_bytes),
        "metrics": metrics,
        "report_markdown": report_markdown,
        "notice": "Analysis is temporary and not saved anywhere."
    }

# ---------------------------------------------------------------------------
# API Routes: SRE Approvals & Audit Trail (Task 5 & Addendum A3)
# ---------------------------------------------------------------------------
@app.get("/api/approvals")
def list_approvals():
    """Lists all approval requests joined with resource metadata, reminders, and comments."""
    query = """
        SELECT a.id, a.resource_id, a.sre_name, a.status, a.action_taken,
               a.reason, a.slack_message_ts, a.decided_at,
               r.type, r.name, r.region, r.est_monthly_cost, r.idle_days,
               r.public_access, s.score, s.risk_bucket,
               i.id as incident_id, b.github_url
        FROM approvals a
        LEFT JOIN resources r ON a.resource_id = r.id
        LEFT JOIN risk_scores s ON r.id = s.resource_id
        LEFT JOIN incidents i ON a.resource_id = i.resource_id
        LEFT JOIN incident_runbooks b ON i.id = b.incident_id
        ORDER BY a.id DESC
    """
    with get_connection() as conn:
        rows = conn.execute(query).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            # Fetch active reminders count
            rem_count = conn.execute(
                "SELECT COUNT(*) FROM reminders WHERE approval_id = ? AND status = 'PENDING'",
                (item["id"],)
            ).fetchone()[0]
            item["pending_reminders_count"] = rem_count

            # Fetch comments count
            com_count = conn.execute(
                "SELECT COUNT(*) FROM comments WHERE approval_id = ?",
                (item["id"],)
            ).fetchone()[0]
            item["comments_count"] = com_count

            result.append(item)

        return {"approvals": result}

@app.patch("/api/approvals/{approval_id}/status")
def update_approval_status(approval_id: int, req: WorkflowStatusUpdate):
    """
    Updates workflow status of an SRE approval row (Pending, In Review, Snoozed, Escalated).
    Approved and Rejected remain read-only displays reflecting Slack decisions.
    """
    clean_status = req.status.strip()
    # Guard: Approved and Rejected cannot be set from Web UI
    if "approved" in clean_status.lower() or "rejected" in clean_status.lower():
        raise HTTPException(
            status_code=400,
            detail="Approved and Rejected actions are restricted to Slack-only execution."
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Approval record not found")

        conn.execute("""
            UPDATE approvals
            SET status = ?, sre_name = ?, action_taken = ?, reason = ?
            WHERE id = ?
        """, (clean_status, req.reviewer, f"Workflow updated to {clean_status}", req.reason, approval_id))

        # Update linked incident
        conn.execute("""
            UPDATE incidents SET status = ?, updated_at = ? WHERE resource_id = ?
        """, (clean_status, now_iso, row["resource_id"]))

    record_live_event("approval_updated", {
        "approval_id": approval_id,
        "resource_id": row["resource_id"],
        "status": clean_status,
        "reviewer": req.reviewer,
        "source": "web_ui",
        "description": f"Approval #{approval_id} workflow transitioned to {clean_status}"
    })

    return {
        "status": "success",
        "approval_id": approval_id,
        "workflow_status": clean_status,
        "updated_at": now_iso
    }

@app.get("/api/approvals/{approval_id}/reminders")
def list_reminders(approval_id: int):
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM reminders WHERE approval_id = ? ORDER BY id DESC", (approval_id,)).fetchall()
        return {"reminders": [dict(r) for r in rows]}

@app.post("/api/approvals/{approval_id}/reminders")
def add_reminder(approval_id: int, req: CreateReminderRequest):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        app_row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not app_row:
            raise HTTPException(status_code=404, detail="Approval record not found")

        cur = conn.execute("""
            INSERT INTO reminders (approval_id, scheduled_time, note, post_to_slack, status, created_at)
            VALUES (?, ?, ?, ?, 'PENDING', ?)
        """, (approval_id, req.scheduled_time, req.note, 1 if req.post_to_slack else 0, now_iso))
        rem_id = cur.lastrowid

    record_live_event("reminder_created", {
        "approval_id": approval_id,
        "reminder_id": rem_id,
        "scheduled_time": req.scheduled_time,
        "description": f"SRE reminder set for approval #{approval_id}"
    })

    return {"status": "success", "reminder_id": rem_id, "scheduled_time": req.scheduled_time}

@app.get("/api/approvals/{approval_id}/comments")
def list_comments(approval_id: int):
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM comments WHERE approval_id = ? ORDER BY id ASC", (approval_id,)).fetchall()
        return {"comments": [dict(r) for r in rows]}

@app.post("/api/approvals/{approval_id}/comments")
def add_comment(approval_id: int, req: CreateCommentRequest):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        app_row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not app_row:
            raise HTTPException(status_code=404, detail="Approval record not found")

        cur = conn.execute("""
            INSERT INTO comments (approval_id, author_name, comment_text, post_to_slack, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (approval_id, req.author_name, req.comment_text, 1 if req.post_to_slack else 0, now_iso))
        comm_id = cur.lastrowid

    record_live_event("comment_added", {
        "approval_id": approval_id,
        "author": req.author_name,
        "description": f"New comment on approval #{approval_id} by {req.author_name}"
    })

    return {"status": "success", "comment_id": comm_id, "author": req.author_name, "created_at": now_iso}

@app.delete("/api/approvals/{approval_id}/comments/{comment_id}")
def delete_comment(approval_id: int, comment_id: int):
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM comments WHERE id = ? AND approval_id = ?", (comment_id, approval_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Comment not found")
    return {"status": "deleted", "comment_id": comment_id}

# ---------------------------------------------------------------------------
# API Routes: Slack Webhooks & Interactivity (Addendum A3)
# ---------------------------------------------------------------------------
@app.post("/slack/interactions")
@app.post("/slack/interactive")
async def handle_slack_interaction_webhook(request: Request):
    """
    Public Slack Interactive Actions endpoint.
    Verifies HMAC-SHA256 signature using SLACK_SIGNING_SECRET.
    Returns HTTP 200 within 3 seconds, syncs database & emits SSE events.
    """
    raw_body = await request.body()
    cfg = get_slack_config()

    # Verify signature if live configured
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
        return Response(content="ok", status_code=200)

    try:
        decision = handle_slack_action_payload(payload)
        res_id = decision.get("resource_id")
        dec_status = decision.get("status")

        # Map to incident status
        inc_status = "Approved" if dec_status == "APPROVED" else (
            "Rejected" if dec_status == "REJECTED" else "Snoozed"
        )

        with get_connection() as conn:
            conn.execute("""
                UPDATE incidents SET status = ?, updated_at = ? WHERE resource_id = ?
            """, (inc_status, datetime.now(timezone.utc).isoformat(), res_id))

        record_live_event("approval_updated", {
            "resource_id": res_id,
            "status": f"{inc_status} (via Slack)",
            "reviewer": decision.get("sre_name"),
            "source": "slack",
            "description": f"SRE {decision.get('sre_name')} {dec_status.lower()} resource via Slack"
        })

        return JSONResponse({"status": "ok", "decision": decision})
    except Exception as e:
        logger.error(f"Error handling Slack interaction: {e}")
        return JSONResponse({"status": "error", "message": str(e)}, status_code=400)

# ---------------------------------------------------------------------------
# Static Web Assets & Frontend Serving
# ---------------------------------------------------------------------------
STATIC_DIR = SCRIPT_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"status": "Frontend initialized. Place index.html in frontend/static/."})

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    logger.info(f"Starting Shadow IT Governance Server on http://0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
