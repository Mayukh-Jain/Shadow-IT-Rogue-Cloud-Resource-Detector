"""
Compatibility bridge for previous slack_service module.
Re-exports functionality from slack-bot/slack_client.py and slack-bot/app.py.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SLACK_BOT_DIR = REPO_ROOT / "slack-bot"
if str(SLACK_BOT_DIR) not in sys.path:
    sys.path.insert(0, str(SLACK_BOT_DIR))

from slack_client import (
    slack_app,
    slack_handler,
    send_slack_alert,
    update_slack_message,
    verify_slack_signature,
    get_slack_config,
    is_live_configured,
)
from app import (
    record_sre_decision,
    process_high_risk_alerts,
    simulate_finding,
    handle_slack_action_payload,
)

__all__ = [
    "slack_app",
    "slack_handler",
    "send_slack_alert",
    "update_slack_message",
    "verify_slack_signature",
    "get_slack_config",
    "is_live_configured",
    "record_sre_decision",
    "process_high_risk_alerts",
    "simulate_finding",
    "handle_slack_action_payload",
]
