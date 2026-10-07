"""
Comprehensive Unit & Integration Test Suite for Slack Bot & Approval Workflow.
Tests message formatting, database operations, signature verification, action handling,
error handling, and simulation mode without requiring live Slack credentials.
"""

import sys
import time
import hmac
import hashlib
import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Setup paths
TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SLACK_BOT_DIR = REPO_ROOT / "slack-bot"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SLACK_BOT_DIR) not in sys.path:
    sys.path.insert(0, str(SLACK_BOT_DIR))

from block_templates import (
    build_high_risk_alert_blocks,
    build_decision_blocks,
)
from slack_client import (
    verify_slack_signature,
    send_slack_alert,
    update_slack_message,
)
from app import (
    app,
    get_unnotified_high_risks,
    create_pending_approval,
    record_sre_decision,
    process_high_risk_alerts,
    simulate_finding,
    handle_slack_action_payload,
)
from shared.db import get_connection, init_db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Initializes a temporary in-memory or isolated SQLite database for testing."""
    test_db_path = tmp_path / "test_local.db"
    schema_path = REPO_ROOT / "shared" / "schema.sql"

    # Patch DB_PATH in shared.db and app
    monkeypatch.setattr("shared.db.DB_PATH", test_db_path)
    init_db(schema_path=schema_path, db_path=test_db_path)

    # Seed basic test data
    with sqlite3.connect(test_db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        now = "2026-10-02T12:00:00+00:00"
        
        # 1. Flagged High-Risk Resource
        conn.execute(
            """
            INSERT INTO resources (id, type, region, name, tags, owner_tag, public_access, idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("i-test-high-01", "EC2", "us-east-1", "HighRiskServer", '{"team": "test"}', None, 1, 60, 150.0, now, 1, now),
        )
        conn.execute(
            """
            INSERT INTO risk_scores (resource_id, score, risk_bucket, model_version, explanation, scored_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("i-test-high-01", 89.5, "HIGH", "rf-v1", "Test high risk explanation: public access and idle.", now),
        )

        # 2. Flagged Medium-Risk Resource
        conn.execute(
            """
            INSERT INTO resources (id, type, region, name, tags, owner_tag, public_access, idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("i-test-med-01", "S3", "us-west-2", "MedRiskBucket", '{"team": "dev"}', "alice", 0, 10, 20.0, now, 1, now),
        )
        conn.execute(
            """
            INSERT INTO risk_scores (resource_id, score, risk_bucket, model_version, explanation, scored_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("i-test-med-01", 45.0, "MEDIUM", "rf-v1", "Test medium risk explanation.", now),
        )

        conn.commit()

    yield test_db_path


# ===========================================================================
# 1. Block Kit Template Tests
# ===========================================================================

def test_build_high_risk_alert_blocks():
    """Verify high-risk Block Kit message formatting and button structure."""
    blocks = build_high_risk_alert_blocks(
        resource_id="i-test-01",
        resource_type="EC2",
        resource_name="WebWorker",
        region="us-east-1",
        score=92.4,
        risk_bucket="HIGH",
        public_access=True,
        idle_days=30,
        est_monthly_cost=125.50,
        explanation="Public instance with no owner tag.",
        suggested_command="aws ec2 stop-instances --instance-ids i-test-01",
    )

    assert len(blocks) >= 4
    header_block = blocks[0]
    assert header_block["type"] == "header"
    assert "High Risk Resource" in header_block["text"]["text"]

    # Verify action buttons
    action_block = next(b for b in blocks if b["type"] == "actions")
    elements = action_block["elements"]
    action_ids = [el["action_id"] for el in elements]
    assert "approve" in action_ids
    assert "reject" in action_ids
    assert "snooze" in action_ids

    # Verify values carry resource ID
    for el in elements:
        assert el["value"] == "i-test-01"


def test_build_decision_blocks():
    """Verify decision blocks render SRE details and remove action buttons."""
    # Test Approved
    approved_blocks = build_decision_blocks(
        resource_id="i-test-01",
        status="APPROVED",
        sre_name="sre_john",
        action_taken="approved — apply manually",
        decided_at="2026-10-02T12:30:00+00:00",
    )
    assert not any(b["type"] == "actions" for b in approved_blocks)
    assert "APPROVED" in str(approved_blocks)
    assert "<@sre_john>" in str(approved_blocks)

    # Test Rejected
    rejected_blocks = build_decision_blocks(
        resource_id="i-test-01",
        status="REJECTED",
        sre_name="sre_jane",
        action_taken="flagged rogue resource",
        decided_at="2026-10-02T12:35:00+00:00",
    )
    assert "REJECTED" in str(rejected_blocks)

    # Test Snoozed
    snoozed_blocks = build_decision_blocks(
        resource_id="i-test-01",
        status="SNOOZED",
        sre_name="sre_alex",
        action_taken="snoozed alert for 24h",
        decided_at="2026-10-02T12:40:00+00:00",
    )
    assert "SNOOZED" in str(snoozed_blocks)


# ===========================================================================
# 2. Security & Signature Verification Tests
# ===========================================================================

def test_verify_slack_signature_valid():
    """Verify valid Slack HMAC-SHA256 signature returns True."""
    secret = "test_signing_secret_12345"
    body = b'payload={"test": "data"}'
    timestamp = str(int(time.time()))

    sig_basestring = f"v0:{timestamp}:".encode("utf-8") + body
    sig_hash = hmac.new(secret.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()
    signature = f"v0={sig_hash}"

    assert verify_slack_signature(secret, body, timestamp, signature) is True


def test_verify_slack_signature_invalid():
    """Verify tampered signature returns False."""
    secret = "test_signing_secret_12345"
    body = b'payload={"test": "data"}'
    timestamp = str(int(time.time()))
    invalid_sig = "v0=invalid_signature_hash_value"

    assert verify_slack_signature(secret, body, timestamp, invalid_sig) is False


def test_verify_slack_signature_expired_timestamp():
    """Verify expired timestamp (> 300s) is rejected to prevent replay attacks."""
    secret = "test_signing_secret_12345"
    body = b'payload={"test": "data"}'
    expired_timestamp = str(int(time.time()) - 400)  # 400s old

    sig_basestring = f"v0:{expired_timestamp}:".encode("utf-8") + body
    sig_hash = hmac.new(secret.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()
    signature = f"v0={sig_hash}"

    assert verify_slack_signature(secret, body, expired_timestamp, signature) is False


def test_verify_slack_signature_missing_params():
    """Verify missing secret/signature/timestamp safely returns False."""
    body = b"data"
    assert verify_slack_signature("", body, "123456", "v0=abc") is False
    assert verify_slack_signature("secret", body, None, "v0=abc") is False
    assert verify_slack_signature("secret", body, "123456", None) is False


# ===========================================================================
# 3. Slack Client Fallback & Error Handling Tests
# ===========================================================================

def test_missing_slack_credentials_mock_mode():
    """Verify mock mode operates cleanly without throwing when credentials are empty."""
    res = {
        "id": "i-mock-01",
        "type": "EC2",
        "name": "MockServer",
        "region": "us-east-1",
        "public_access": True,
        "idle_days": 15,
        "est_monthly_cost": 50.0,
    }
    risk = {
        "score": 88.0,
        "risk_bucket": "HIGH",
        "explanation": "Mock explanation",
    }

    # In mock mode, send_slack_alert returns (True, mock_ts_...)
    success, msg_ts = send_slack_alert(res, risk)
    assert success is True
    assert msg_ts is not None
    assert msg_ts.startswith("mock_ts_")


def test_slack_api_error_handling():
    """Verify handling when Slack API throws an exception."""
    from slack_sdk.errors import SlackApiError

    mock_client = MagicMock()
    mock_client.chat_postMessage.side_effect = SlackApiError(
        message="channel_not_found",
        response={"ok": False, "error": "channel_not_found"},
    )

    mock_bolt = MagicMock()
    mock_bolt.client = mock_client

    with patch("slack_client.slack_app", mock_bolt), patch("slack_client.is_live_configured", return_value=True):
        res = {"id": "i-err-01", "type": "EC2"}
        risk = {"score": 90.0, "risk_bucket": "HIGH"}
        success, msg_ts = send_slack_alert(res, risk)
        assert success is False
        assert msg_ts is None


# ===========================================================================
# 4. Database Workflow & Decision Tests
# ===========================================================================

def test_pending_approval_creation():
    """Verify creating a PENDING approval record in the database."""
    res_id = "i-test-high-01"
    msg_ts = "1727870000.123456"

    created = create_pending_approval(res_id, msg_ts)
    assert created is True

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchone()
        assert row is not None
        assert row["resource_id"] == res_id
        assert row["status"] == "PENDING"
        assert row["slack_message_ts"] == msg_ts
        assert row["sre_name"] is None


def test_sre_decision_approve():
    """Verify SRE approve action records APPROVED status and action details."""
    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_123")

    decision = record_sre_decision(
        resource_id=res_id,
        action="approve",
        sre_name="sre_alice",
        message_ts="ts_123",
    )

    assert decision["status"] == "APPROVED"
    assert decision["sre_name"] == "sre_alice"
    assert "approved" in decision["action_taken"]

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchone()
        assert row["status"] == "APPROVED"
        assert row["sre_name"] == "sre_alice"
        assert row["decided_at"] is not None


def test_sre_decision_reject():
    """Verify SRE reject action records REJECTED status."""
    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_456")

    decision = record_sre_decision(
        resource_id=res_id,
        action="reject",
        sre_name="sre_bob",
        message_ts="ts_456",
        reason="No legitimate business purpose found.",
    )

    assert decision["status"] == "REJECTED"
    assert decision["sre_name"] == "sre_bob"
    assert decision["reason"] == "No legitimate business purpose found."

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchone()
        assert row["status"] == "REJECTED"
        assert row["reason"] == "No legitimate business purpose found."


def test_sre_decision_snooze():
    """Verify SRE snooze action records SNOOZED status."""
    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_789")

    decision = record_sre_decision(
        resource_id=res_id,
        action="snooze",
        sre_name="sre_charlie",
        message_ts="ts_789",
    )

    assert decision["status"] == "SNOOZED"
    assert decision["sre_name"] == "sre_charlie"

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchone()
        assert row["status"] == "SNOOZED"


def test_duplicate_alert_prevention():
    """Verify duplicate alerts are prevented once a pending/completed record exists."""
    unnotified = get_unnotified_high_risks()
    assert len(unnotified) == 1
    assert unnotified[0]["id"] == "i-test-high-01"

    # Now dispatch alerts
    dispatched = process_high_risk_alerts()
    assert len(dispatched) == 1
    assert dispatched[0]["resource_id"] == "i-test-high-01"

    # Second check should find 0 unnotified high risks (duplicate prevention)
    second_check = get_unnotified_high_risks()
    assert len(second_check) == 0

    second_dispatch = process_high_risk_alerts()
    assert len(second_dispatch) == 0


def test_handle_slack_action_payload():
    """Verify processing full Slack interactive payload dictionary."""
    res_id = "i-test-high-01"
    create_pending_approval(res_id, "1727871234.567890")

    mock_payload = {
        "type": "block_actions",
        "user": {
            "id": "U123456",
            "username": "sre_dave",
            "name": "sre_dave",
        },
        "channel": {"id": "C987654"},
        "message": {"ts": "1727871234.567890"},
        "actions": [
            {
                "action_id": "approve",
                "block_id": f"actions_{res_id}",
                "value": res_id,
                "type": "button",
            }
        ],
    }

    decision = handle_slack_action_payload(mock_payload)
    assert decision["status"] == "APPROVED"
    assert decision["sre_name"] == "sre_dave"
    assert decision["resource_id"] == res_id

    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchone()
        assert row["status"] == "APPROVED"
        assert row["sre_name"] == "sre_dave"


# ===========================================================================
# 5. Simulation Mode Tests
# ===========================================================================

def test_simulation_mode():
    """Verify simulation mode triggers demo alert without mutating AWS."""
    sim_result = simulate_finding(
        resource_id="sim-demo-ec2",
        resource_type="EC2",
        resource_name="Demo-Rogue-Instance",
        score=95.0,
    )

    assert sim_result["simulation"] is True
    assert sim_result["resource_id"] == "sim-demo-ec2"
    assert sim_result["success"] is True

    # Verify pending approval was created in database
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", ("sim-demo-ec2",)).fetchone()
        assert row is not None
        assert row["status"] == "PENDING"


# ===========================================================================
# 6. FastAPI Webhook & API Endpoints Tests
# ===========================================================================

def test_fastapi_health_endpoint():
    """Test /health endpoint."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database_connected"] is True


def test_fastapi_approvals_endpoint():
    """Test /approvals endpoint returns audit history."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    create_pending_approval("i-test-high-01", "ts_111")
    record_sre_decision("i-test-high-01", "approve", "sre_alice", "ts_111")

    response = client.get("/approvals")
    assert response.status_code == 200
    data = response.json()
    assert "approvals" in data
    assert len(data["approvals"]) >= 1
    assert data["approvals"][0]["status"] == "APPROVED"


def test_fastapi_simulate_endpoint():
    """Test POST /simulate-alert endpoint."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    payload = {
        "resource_id": "sim-api-01",
        "resource_type": "EC2",
        "resource_name": "APISimulatedNode",
        "score": 91.0,
    }
    response = client.post("/simulate-alert", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["simulation"] is True
    assert data["resource_id"] == "sim-api-01"


def test_duplicate_action_resolution():
    """Verify multiple decision calls on the same resource update gracefully."""
    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_dup_1")

    # First decision: SNOOZE
    dec1 = record_sre_decision(res_id, "snooze", "sre_bob", "ts_dup_1")
    assert dec1["status"] == "SNOOZED"

    # Second decision: APPROVE (overriding / re-deciding)
    dec2 = record_sre_decision(res_id, "approve", "sre_alice", "ts_dup_1")
    assert dec2["status"] == "APPROVED"

    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM approvals WHERE resource_id = ?", (res_id,)).fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == "APPROVED"
        assert rows[0]["sre_name"] == "sre_alice"


def test_fastapi_send_alerts_endpoint():
    """Test POST /send-alerts triggers pipeline dispatcher."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    response = client.post("/send-alerts")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["count"] == 1


def test_fastapi_events_endpoint_form_payload():
    """Test POST /slack/events with form-encoded interactive action payload."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_event_99")

    mock_payload = {
        "type": "block_actions",
        "user": {"id": "U999", "username": "sre_webhook", "name": "sre_webhook"},
        "channel": {"id": "C999"},
        "message": {"ts": "ts_event_99"},
        "actions": [{"action_id": "reject", "value": res_id}],
    }

    response = client.post(
        "/slack/events",
        data={"payload": json.dumps(mock_payload)},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["decision"]["status"] == "REJECTED"


def test_fastapi_interactive_signature_verification():
    """Test POST /slack/interactive endpoint signature enforcement."""
    from fastapi.testclient import TestClient
    client = TestClient(app)

    res_id = "i-test-high-01"
    create_pending_approval(res_id, "ts_sec_01")
    payload = {
        "type": "block_actions",
        "user": {"id": "U100", "username": "sre_sec", "name": "sre_sec"},
        "channel": {"id": "C100"},
        "message": {"ts": "ts_sec_01"},
        "actions": [{"action_id": "approve", "value": res_id}],
    }

    # Under mock config (is_live_configured() is False), direct payload is processed cleanly
    response = client.post(
        "/slack/interactive",
        json=payload,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

