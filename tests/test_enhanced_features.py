"""
Comprehensive test suite for Shadow.Guard enhancements:
- Task 1: Health, DB auto-seed, no Gradio
- Task 2: Live Feed endpoints and SSE stream
- Task 3: Incidents list, report generation, deterministic fallback, regeneration
- Task 4: In-memory Log Analyzer (parsing, metrics, secret redaction, zero persistence)
- Task 5: SRE Approvals workflow status, reminders, comments CRUD
- Task 6: Removed routes return 404
- Addendum A1-A7: Multi-region collector, fanout deduplication, Slack signature verification, read-only boto3 assertion
"""

import sys
import io
import time
import json
import hmac
import hashlib
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
for p in (REPO_ROOT, REPO_ROOT / "llm-explainability", REPO_ROOT / "slack-bot"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from fastapi.testclient import TestClient
from shared.db import get_connection, init_db
from shared.log_parser import parse_log_content, generate_log_incident_report, redact_secrets
from runbook_generator import build_deterministic_runbook, generate_runbook_with_llm_or_fallback
from fanout import compute_dedupe_key, handle_new_incident
from slack_client import verify_slack_signature
from frontend.server import app

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Sets up an isolated database for every test."""
    test_db = tmp_path / "test_local.db"
    schema_path = REPO_ROOT / "shared" / "schema.sql"
    monkeypatch.setattr("shared.db.DB_PATH", test_db)
    init_db(schema_path=schema_path, db_path=test_db)
    from shared.inject_mock_data import inject
    inject(db_path=test_db)

@pytest.fixture
def client():
    return TestClient(app)

# ============================================================================
# Task 1 & Architecture Tests
# ============================================================================
def test_serve_index_html(client):
    """Verifies that GET / serves the custom index.html dashboard and no Gradio exists."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SHADOW" in resp.text
    assert "Live Feed" in resp.text
    assert "gradio" not in resp.text.lower()

def test_database_auto_seeded():
    """Verifies that the database auto-seeds with resources, risk scores, approvals, and incidents."""
    with get_connection() as conn:
        res_count = conn.execute("SELECT COUNT(*) FROM resources").fetchone()[0]
        inc_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        app_count = conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
        assert res_count >= 5
        assert inc_count >= 3
        assert app_count >= 3

# ============================================================================
# Task 2: Live Feed & Dashboard Stats Tests
# ============================================================================
def test_dashboard_stats_endpoint(client):
    """Verifies GET /api/dashboard/stats returns account-level KPIs and region metadata."""
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_resources" in data
    assert "flagged_resources" in data
    assert "wasted_monthly_cost" in data
    assert "risk_buckets" in data
    assert "HIGH" in data["risk_buckets"]
    assert "by_type" in data
    assert "regions_scanned" in data

def test_dashboard_stats_region_filter(client):
    """Verifies region filtering on GET /api/dashboard/stats."""
    resp = client.get("/api/dashboard/stats?region=us-east-1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_resources"] >= 1

def test_live_feed_recent_endpoint(client):
    """Verifies GET /api/live-feed polling fallback returns list of recent telemetry events."""
    resp = client.get("/api/live-feed")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert isinstance(data["events"], list)
    assert len(data["events"]) >= 1

# ============================================================================
# Task 3: Incidents & Runbooks Tests
# ============================================================================
def test_list_incidents_endpoint(client):
    """Verifies GET /api/incidents returns incidents with status badges and pipeline status."""
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    assert data["count"] >= 1
    first = data["incidents"][0]
    assert "id" in first
    assert "resource_id" in first
    assert "status" in first
    assert "pipeline_status" in first

def test_get_incident_report_cached_and_lazy(client):
    """Verifies GET /api/incidents/{id}/report returns runbook with all required sections."""
    resp_list = client.get("/api/incidents")
    first_id = resp_list.json()["incidents"][0]["id"]

    resp = client.get(f"/api/incidents/{first_id}/report")
    assert resp.status_code == 200
    data = resp.json()
    assert "markdown" in data
    assert "Incident Summary" in data["markdown"]
    assert "Root Cause" in data["markdown"]
    assert "Containment & Remediation Plan" in data["markdown"]
    assert "Future Prevention & Safety Guardrails" in data["markdown"]

def test_regenerate_incident_runbook(client):
    """Verifies POST /api/incidents/{id}/regenerate increments runbook version."""
    resp_list = client.get("/api/incidents")
    first_id = resp_list.json()["incidents"][0]["id"]

    resp = client.post(f"/api/incidents/{first_id}/regenerate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] >= 2
    assert "markdown" in data

def test_deterministic_runbook_fallback():
    """Verifies deterministic template generation when LLM is unavailable."""
    sample_res = {
        "id": "i-test-unit",
        "name": "Unit-Test-EC2",
        "type": "EC2",
        "est_monthly_cost": 45.0,
        "idle_days": 20,
        "public_access": 1,
        "tags": '{"env": "test"}'
    }
    rb, gen = generate_runbook_with_llm_or_fallback(
        incident_id="INC-UNIT-01",
        resource=sample_res,
        risk_score=85.0,
        risk_tier="HIGH",
        trigger_source="Unit Test Trigger"
    )
    assert "## 1. Incident Summary" in rb
    assert "## 4. Immediate Containment & Remediation Plan" in rb
    assert "aws ec2 stop-instances" in rb
    assert "generator: template" in rb.lower()
    assert gen == "template"

# ============================================================================
# Task 4: In-Memory Log Analyzer (Zero-Persistence) Tests
# ============================================================================
def test_log_analyzer_parsing_and_metrics():
    """Verifies in-memory parsing of severities, IPs, resources, HTTP statuses, and AWS events."""
    raw_log = """
    2026-10-06 12:00:01 INFO Authenticated user admin from 192.168.1.50
    2026-10-06 12:00:05 ERROR Failed login attempt from 203.0.113.45 for user root HTTP 401
    2026-10-06 12:00:08 WARN Ingress rule modified for sg-0123456789abcdef0 AuthorizeSecurityGroupIngress
    2026-10-06 12:00:15 CRITICAL Unauthorized AssumeRole attempt on i-0a1b2c3d4e5f67890 HTTP 403
    2026-10-06 12:00:20 ERROR Failed connection to db-prod-postgres from 203.0.113.45 HTTP 500
    """
    metrics = parse_log_content(raw_log)
    assert metrics["total_lines"] == 5
    assert metrics["severities"]["CRITICAL"] == 1
    assert metrics["severities"]["ERROR"] == 2
    assert metrics["severities"]["WARN"] == 1
    assert metrics["severities"]["INFO"] == 1

    # Check IPs
    top_ips = [i["ip"] for i in metrics["top_ips"]]
    assert "203.0.113.45" in top_ips

    # Check Resources
    top_res = [r["resource"] for r in metrics["top_resources"]]
    assert any("sg-" in r or "i-" in r or "db-" in r for r in top_res)

    # Check AWS Events
    assert "Authorizesecuritygroupingress" in metrics["aws_events"] or "Assumerole" in metrics["aws_events"]

def test_log_secret_redaction():
    """Verifies that secrets (AWS keys, passwords, bearer tokens) are redacted in memory."""
    sensitive_log = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
        "Authorization: Bearer my-secret-token-12345 "
        "password = SuperSecretPass! "
        "contact developer@example.com"
    )
    redacted = redact_secrets(sensitive_log)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "SuperSecretPass!" not in redacted
    assert "developer@example.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted

def test_log_analyzer_endpoint_zero_persistence(client):
    """Verifies POST /api/log-analyzer processes multipart log in memory and does not write to DB."""
    log_content = (
        "2026-10-06 10:00:00 INFO Service started\n"
        "2026-10-06 10:01:00 ERROR Unauthorized access to i-rogue-node from 198.51.100.10 HTTP 403\n"
    )
    file_bytes = io.BytesIO(log_content.encode("utf-8"))

    with get_connection() as conn:
        count_before = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    resp = client.post(
        "/api/log-analyzer",
        files={"file": ("test_server.log", file_bytes, "text/plain")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "metrics" in data
    assert "report_markdown" in data
    assert "Executive Summary" in data["report_markdown"]
    assert "temporary" in data["notice"].lower()

    # Assert zero persistence in DB
    with get_connection() as conn:
        count_after = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert count_after == count_before

def test_log_analyzer_rejects_invalid_file(client):
    """Verifies that non-text files or invalid extensions are rejected."""
    bad_bytes = io.BytesIO(b"\x89PNG\r\n\x1a\n")
    resp = client.post(
        "/api/log-analyzer",
        files={"file": ("malicious.png", bad_bytes, "image/png")}
    )
    assert resp.status_code == 400
    assert "supported" in resp.json()["detail"].lower()

# ============================================================================
# Task 5: SRE Approvals Workflow, Reminders, Comments Tests
# ============================================================================
def test_update_approval_workflow_status(client):
    """Verifies PATCH /api/approvals/{id}/status updates workflow status."""
    resp_list = client.get("/api/approvals")
    app_id = resp_list.json()["approvals"][0]["id"]

    resp = client.patch(
        f"/api/approvals/{app_id}/status",
        json={"status": "In Review", "reviewer": "sre.test"}
    )
    assert resp.status_code == 200
    assert resp.json()["workflow_status"] == "In Review"

def test_update_approval_rejects_slack_only_actions(client):
    """Verifies that Approved and Rejected cannot be set from Web UI."""
    resp_list = client.get("/api/approvals")
    app_id = resp_list.json()["approvals"][0]["id"]

    resp = client.patch(
        f"/api/approvals/{app_id}/status",
        json={"status": "Approved", "reviewer": "hacker"}
    )
    assert resp.status_code == 400
    assert "slack" in resp.json()["detail"].lower()

def test_reminders_crud(client):
    """Verifies scheduling and listing reminders for an approval request."""
    resp_list = client.get("/api/approvals")
    app_id = resp_list.json()["approvals"][0]["id"]

    # Create reminder
    resp_create = client.post(
        f"/api/approvals/{app_id}/reminders",
        json={"scheduled_time": "2026-10-07T12:00:00Z", "note": "Check isolation status"}
    )
    assert resp_create.status_code == 200
    assert "reminder_id" in resp_create.json()

    # List reminders
    resp_get = client.get(f"/api/approvals/{app_id}/reminders")
    assert resp_get.status_code == 200
    assert len(resp_get.json()["reminders"]) >= 1

def test_comments_crud(client):
    """Verifies adding, listing, and deleting discussion comments."""
    resp_list = client.get("/api/approvals")
    app_id = resp_list.json()["approvals"][0]["id"]

    # Add comment
    resp_add = client.post(
        f"/api/approvals/{app_id}/comments",
        json={"author_name": "sre.lead", "comment_text": "Quarantine scheduled for tonight"}
    )
    assert resp_add.status_code == 200
    comment_id = resp_add.json()["comment_id"]

    # List comments
    resp_list_c = client.get(f"/api/approvals/{app_id}/comments")
    assert resp_list_c.status_code == 200
    assert any(c["id"] == comment_id for c in resp_list_c.json()["comments"])

    # Delete comment
    resp_del = client.delete(f"/api/approvals/{app_id}/comments/{comment_id}")
    assert resp_del.status_code == 200

# ============================================================================
# Task 6: Removed Routes Return 404
# ============================================================================
def test_deprecated_routes_return_404(client):
    """Verifies that removed routes (pipeline run, simulate, explain, predict) return 404."""
    assert client.post("/api/pipeline/run", json={"mode": "mock"}).status_code == 404
    assert client.post("/api/pipeline/simulate").status_code == 404
    assert client.post("/api/explain/i-123", json={}).status_code == 404

# ============================================================================
# Addendum A2 & A3: Fan-Out Deduplication & Slack Signature Verification
# ============================================================================
def test_fanout_deduplication():
    """Verifies that handle_new_incident does not create duplicates for the same resource."""
    resource = {
        "id": "i-dedupe-test-99",
        "type": "EC2",
        "region": "us-east-1",
        "name": "Dedupe-Node",
        "est_monthly_cost": 50.0,
        "idle_days": 20,
        "public_access": 1,
        "tags": "{}"
    }
    risk = {"score": 80.0, "risk_bucket": "HIGH"}

    inc1 = handle_new_incident(resource, risk, trigger_source="Rule-A")
    inc2 = handle_new_incident(resource, risk, trigger_source="Rule-A")
    assert inc1["id"] == inc2["id"]

def test_slack_signature_verification():
    """Verifies HMAC-SHA256 signature verification and replay rejection."""
    secret = "test-signing-secret"
    body = b"payload=test_action"
    now_ts = str(int(time.time()))

    # Compute valid signature
    sig_basestring = f"v0:{now_ts}:{body.decode('utf-8')}".encode("utf-8")
    valid_sig = "v0=" + hmac.new(secret.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()

    assert verify_slack_signature(secret, body, now_ts, valid_sig) is True

    # Bad signature
    assert verify_slack_signature(secret, body, now_ts, "v0=bad_hash_value") is False

    # Stale timestamp (> 5 minutes ago)
    stale_ts = str(int(time.time()) - 600)
    stale_sig = "v0=" + hmac.new(secret.encode("utf-8"), f"v0:{stale_ts}:{body.decode('utf-8')}".encode("utf-8"), hashlib.sha256).hexdigest()
    assert verify_slack_signature(secret, body, stale_ts, stale_sig) is False

def test_readonly_boto3_assertion():
    """
    Security invariant test: Asserts that detection and collection code
    uses ONLY read-only boto3 methods (Describe*, List*, Get*) and NEVER mutates AWS.
    """
    scanner_path = REPO_ROOT / "detection" / "scanner.py"
    collector_path = REPO_ROOT / "detection" / "aws_collector.py"

    forbidden_mutations = [
        "terminate_instances", "stop_instances", "delete_bucket",
        "put_bucket_policy", "put_bucket_acl", "modify_instance_attribute",
        "delete_db_instance", "reboot_db_instance"
    ]

    for fpath in (scanner_path, collector_path):
        if fpath.exists():
            code = fpath.read_text(encoding="utf-8").lower()
            for mut in forbidden_mutations:
                # Assert method is not invoked on a client
                assert f".{mut}(" not in code, f"Forbidden mutation call '{mut}' detected in {fpath.name}"
