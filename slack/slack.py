"""
Compatibility bridge for previous slack module.
Points to the new Shadow IT Slack Bot implementation in slack-bot/.
"""

import os
import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
SLACK_BOT_DIR = REPO_ROOT / "slack-bot"
if str(SLACK_BOT_DIR) not in sys.path:
    sys.path.insert(0, str(SLACK_BOT_DIR))

from app import simulate_finding, process_high_risk_alerts
from slack_client import send_slack_alert

router = APIRouter()


class SendAlertRequest(BaseModel):
    resource_id: str


@router.post("/send-alert")
def trigger_alert(request: SendAlertRequest):
    """Trigger alert for a specific resource ID."""
    dispatched = process_high_risk_alerts()
    return {
        "status": "success",
        "channel": os.getenv("SLACK_CHANNEL", "#shadow-it-alerts"),
        "dispatched": dispatched,
    }


@router.post("/simulate")
def trigger_simulation():
    """Trigger demo simulated high-risk alert."""
    return simulate_finding()
