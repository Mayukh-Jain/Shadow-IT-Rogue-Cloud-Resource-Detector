"""
Slack Block Kit message templates for Shadow IT / Rogue Cloud Resource Detector.
Provides modular and reusable Block Kit JSON builders for alerts and audit updates.
"""

from typing import Dict, Any, Optional, List


def build_high_risk_alert_blocks(
    resource_id: str,
    resource_type: str,
    resource_name: Optional[str],
    region: Optional[str],
    score: float,
    risk_bucket: str,
    public_access: bool,
    idle_days: int,
    est_monthly_cost: float,
    explanation: Optional[str],
    suggested_command: Optional[str] = None,
    is_simulation: bool = False,
) -> List[Dict[str, Any]]:
    """
    Builds Slack Block Kit blocks for a HIGH-risk Shadow IT finding alert with interactive buttons.
    """
    sim_banner = "🧪 *[SIMULATION MODE]* " if is_simulation else ""
    res_name = resource_name or "N/A"
    res_region = region or "Unknown"
    pa_text = "⚠️ Yes (Public)" if public_access else "🔒 No (Private)"
    cost_text = f"${est_monthly_cost:.2f}/mo"
    expl_text = explanation or "No detailed explanation generated. Immediate review recommended."

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 {sim_banner}Shadow IT Alert: High Risk Resource",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Resource ID:*\n`{resource_id}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Type / Name:*\n{resource_type} ({res_name})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Region:*\n{res_region}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Score:*\n🔥 *{score:.1f} / 100* (`{risk_bucket}`)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Public Access:*\n{pa_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Idle / Cost:*\n{idle_days} days | {cost_text}",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🤖 AI Risk Analysis & Suggested Remediation:*\n{expl_text}",
            },
        },
    ]

    if suggested_command:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Suggested CLI Command:*\n```{suggested_command}```",
            },
        })

    blocks.extend([
        {"type": "divider"},
        {
            "type": "actions",
            "block_id": f"actions_{resource_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "✅ Approve (Keep / Valid)",
                        "emoji": True,
                    },
                    "style": "primary",
                    "action_id": "approve",
                    "value": resource_id,
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "❌ Reject (Flag Rogue)",
                        "emoji": True,
                    },
                    "style": "danger",
                    "action_id": "reject",
                    "value": resource_id,
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "⏳ Snooze (24h)",
                        "emoji": True,
                    },
                    "action_id": "snooze",
                    "value": resource_id,
                },
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Shadow IT Detector* | Human-in-the-Loop SRE Review Required",
                }
            ],
        },
    ])

    return blocks


def build_decision_blocks(
    resource_id: str,
    status: str,
    sre_name: str,
    action_taken: str,
    decided_at: str,
    original_details: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Builds Slack Block Kit blocks updating the original alert with the final SRE decision,
    removing all action buttons for a permanent audit trail.
    """
    status_upper = status.upper()
    if status_upper == "APPROVED":
        status_badge = "✅ *APPROVED*"
        status_icon = "✅"
    elif status_upper == "REJECTED":
        status_badge = "❌ *REJECTED / MARKED ROGUE*"
        status_icon = "❌"
    elif status_upper == "SNOOZED":
        status_badge = "⏳ *SNOOZED (24h)*"
        status_icon = "⏳"
    else:
        status_badge = f"ℹ️ *{status_upper}*"
        status_icon = "ℹ️"

    user_mention = f"<@{sre_name}>" if not sre_name.startswith("@") and not sre_name.startswith("<@") else sre_name

    fields = [
        {
            "type": "mrkdwn",
            "text": f"*Resource ID:*\n`{resource_id}`",
        },
        {
            "type": "mrkdwn",
            "text": f"*Decision Status:*\n{status_badge}",
        },
        {
            "type": "mrkdwn",
            "text": f"*Reviewed By:*\n{user_mention}",
        },
        {
            "type": "mrkdwn",
            "text": f"*Decision Time:*\n`{decided_at}`",
        },
    ]

    if action_taken:
        fields.append({
            "type": "mrkdwn",
            "text": f"*Action Recorded:*\n{action_taken}",
        })

    if reason:
        fields.append({
            "type": "mrkdwn",
            "text": f"*Reason / Notes:*\n{reason}",
        })

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} SRE Review Completed: {resource_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": fields,
        },
    ]

    if original_details:
        res_type = original_details.get("type", "Resource")
        score = original_details.get("score", "N/A")
        expl = original_details.get("explanation", "")
        if expl:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Original Finding ({res_type}, Risk: {score}/100):*\n_{expl}_",
                },
            })

    blocks.extend([
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🔒 *Audit trail saved to database.* Action buttons disabled.",
                }
            ],
        },
    ])

    return blocks
