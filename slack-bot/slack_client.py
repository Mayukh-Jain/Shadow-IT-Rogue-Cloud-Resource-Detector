"""
Slack Client & Communication Layer for Shadow IT / Rogue Cloud Resource Detector.
Manages Slack Bolt initialization, request signature verification, message posting,
and message updating with robust fallback/mock support for offline development and tests.
"""

import os
import time
import hmac
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.fastapi import SlackRequestHandler
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Load environment variables
load_dotenv()

# Setup module logger
logger = logging.getLogger("shadow-it-detector.slack-client")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def get_slack_config() -> Dict[str, str]:
    """Retrieve Slack configuration from environment variables."""
    bot_token = os.getenv("SLACK_BOT_TOKEN", "").strip()
    signing_secret = os.getenv("SLACK_SIGNING_SECRET", "").strip()
    channel = os.getenv("SLACK_CHANNEL") or os.getenv("SLACK_CHANNEL_ID") or "#shadow-it-alerts"
    app_token = os.getenv("SLACK_APP_TOKEN", "").strip()
    return {
        "bot_token": bot_token,
        "signing_secret": signing_secret,
        "channel": channel,
        "app_token": app_token,
    }


def is_live_configured() -> bool:
    """Check if valid, non-placeholder Slack credentials exist."""
    cfg = get_slack_config()
    token = cfg["bot_token"]
    secret = cfg["signing_secret"]
    if not token or not secret:
        return False
    if token.startswith("xoxb-your") or token.startswith("xoxb-placeholder"):
        return False
    if secret.startswith("your-") or secret == "placeholder":
        return False
    return True


def initialize_slack_bolt() -> Tuple[Optional[App], Optional[SlackRequestHandler]]:
    """
    Initializes Slack Bolt App and FastAPI RequestHandler if valid credentials are present.
    Returns (None, None) in mock/simulation mode.
    """
    cfg = get_slack_config()
    if is_live_configured():
        try:
            bolt_app = App(
                token=cfg["bot_token"],
                signing_secret=cfg["signing_secret"],
            )
            req_handler = SlackRequestHandler(bolt_app)
            logger.info("Slack Bolt App initialized successfully in LIVE mode.")
            return bolt_app, req_handler
        except Exception as e:
            logger.error(f"Failed to initialize Slack Bolt App: {e}")
            return None, None
    else:
        logger.warning(
            "Slack credentials are not configured or contain placeholder values. "
            "Slack service will run in MOCK / SIMULATION mode."
        )
        return None, None


# Global singleton instances
slack_app, slack_handler = initialize_slack_bolt()


def verify_slack_signature(
    signing_secret: str,
    request_body: bytes,
    timestamp: Optional[str],
    signature: Optional[str],
    max_time_diff_seconds: int = 300,
) -> bool:
    """
    Validates the authenticity of incoming Slack webhook requests.
    Prevents replay attacks by checking timestamp tolerance, and performs constant-time
    HMAC-SHA256 signature verification.
    """
    if not signing_secret or not timestamp or not signature:
        logger.warning("Verification failed: Missing signing secret, timestamp, or signature header.")
        return False

    try:
        req_ts = int(timestamp)
    except (ValueError, TypeError):
        logger.warning(f"Verification failed: Invalid timestamp format '{timestamp}'.")
        return False

    # Prevent replay attacks (> 5 minutes difference)
    current_time = int(time.time())
    if abs(current_time - req_ts) > max_time_diff_seconds:
        logger.warning(
            f"Verification failed: Timestamp expired (diff={abs(current_time - req_ts)}s > {max_time_diff_seconds}s)."
        )
        return False

    # Compute expected signature: v0=HMAC_SHA256(secret, "v0:" + timestamp + ":" + body)
    sig_basestring = f"v0:{timestamp}:".encode("utf-8") + request_body
    computed_hash = hmac.new(
        signing_secret.encode("utf-8"),
        sig_basestring,
        hashlib.sha256,
    ).hexdigest()
    expected_signature = f"v0={computed_hash}"

    # Use constant-time comparison to prevent timing attacks
    is_valid = hmac.compare_digest(expected_signature, signature)
    if not is_valid:
        logger.warning("Verification failed: Signature mismatch.")
    return is_valid


def send_slack_alert(
    resource: Dict[str, Any],
    risk: Dict[str, Any],
    explanation: Optional[str] = None,
    suggested_command: Optional[str] = None,
    is_simulation: bool = False,
    channel_override: Optional[str] = None,
    dashboard_url: Optional[str] = None,
    github_runbook_url: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Constructs and sends a High-Risk finding alert to Slack.
    
    Returns:
        Tuple[bool, Optional[str]]: (success, slack_message_ts)
    """
    from block_templates import build_high_risk_alert_blocks

    cfg = get_slack_config()
    target_channel = channel_override or cfg["channel"]
    res_id = str(resource.get("id", "unknown-res"))
    res_type = str(resource.get("type", "AWS::Resource"))
    res_name = resource.get("name")
    res_region = resource.get("region")
    score = float(risk.get("score", 0.0))
    risk_bucket = str(risk.get("risk_bucket", "HIGH"))
    public_access = bool(resource.get("public_access", False))
    idle_days = int(resource.get("idle_days", 0))
    cost = float(resource.get("est_monthly_cost", 0.0))
    expl_text = explanation or risk.get("explanation")

    blocks = build_high_risk_alert_blocks(
        resource_id=res_id,
        resource_type=res_type,
        resource_name=res_name,
        region=res_region,
        score=score,
        risk_bucket=risk_bucket,
        public_access=public_access,
        idle_days=idle_days,
        est_monthly_cost=cost,
        explanation=expl_text,
        suggested_command=suggested_command,
        is_simulation=is_simulation,
        dashboard_url=dashboard_url,
        github_runbook_url=github_runbook_url,
        incident_id=incident_id,
    )

    fallback_text = f"🚨 High Risk Shadow IT Alert: {res_id} ({res_type}) - Score {score:.1f}/100"

    # MOCK MODE if Slack is not configured or app initialization was skipped
    if not slack_app or not is_live_configured():
        mock_ts = f"mock_ts_{int(time.time())}_{res_id}"
        logger.info(
            f"[MOCK SLACK] Alert generated for resource {res_id} (Channel: {target_channel}). Generated mock ts: {mock_ts}"
        )
        return True, mock_ts

    try:
        response = slack_app.client.chat_postMessage(
            channel=target_channel,
            text=fallback_text,
            blocks=blocks,
        )
        msg_ts = response.get("ts")
        logger.info(f"Slack alert sent successfully for {res_id} to {target_channel} (ts={msg_ts})")
        return True, msg_ts
    except SlackApiError as e:
        logger.error(f"Slack API error posting alert for {res_id}: {e.response.get('error')}")
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error posting alert for {res_id}: {e}")
        return False, None


def update_slack_message(
    channel_id: str,
    message_ts: str,
    resource_id: str,
    status: str,
    sre_name: str,
    action_taken: str,
    decided_at: str,
    client: Optional[WebClient] = None,
    original_details: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
) -> bool:
    """
    Updates the original Slack alert message to reflect the SRE's decision and removes interactive buttons.
    """
    from block_templates import build_decision_blocks

    blocks = build_decision_blocks(
        resource_id=resource_id,
        status=status,
        sre_name=sre_name,
        action_taken=action_taken,
        decided_at=decided_at,
        original_details=original_details,
        reason=reason,
    )

    fallback_text = f"SRE Decision: {status.upper()} for {resource_id} by {sre_name}"

    if not is_live_configured() or message_ts.startswith("mock_ts_"):
        logger.info(
            f"[MOCK SLACK] Updated message {message_ts} in channel {channel_id} with status={status} by {sre_name}"
        )
        return True

    active_client = client or (slack_app.client if slack_app else None)
    if not active_client:
        logger.warning(f"Cannot update message {message_ts}: No active Slack client.")
        return False

    try:
        active_client.chat_update(
            channel=channel_id,
            ts=message_ts,
            text=fallback_text,
            blocks=blocks,
        )
        logger.info(f"Updated Slack message {message_ts} with decision {status} by {sre_name}")
        return True
    except SlackApiError as e:
        logger.error(f"Slack API error updating message {message_ts}: {e.response.get('error')}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error updating Slack message {message_ts}: {e}")
        return False
