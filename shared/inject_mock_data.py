"""
Mock data injector for Shadow IT Detector.
Populates local database with diverse cloud resources, risk scores, approvals, and incidents.
"""
import sqlite3
import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

SHARED_DIR = Path(__file__).resolve().parent
REPO_ROOT = SHARED_DIR.parent
DB_PATH = SHARED_DIR / "local.db"
SCHEMA_PATH = SHARED_DIR / "schema.sql"

if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

def init_db_if_missing(db_path=None):
    from db import init_db
    init_db(schema_path=SCHEMA_PATH, db_path=db_path or DB_PATH)

def generate_dedupe_key(account_id: str, region: str, res_id: str, rule: str = "default") -> str:
    raw = f"{account_id}:{region}:{res_id}:{rule}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def inject(db_path=None):
    target_db = Path(db_path) if db_path else DB_PATH
    init_db_if_missing(target_db)
    
    with sqlite3.connect(str(target_db)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        
        now = datetime.now(timezone.utc)
        
        mock_resources = [
            # 1. High risk rogue EC2
            {
                "id": "i-0a8b7c6d5e4f3a2b1",
                "type": "EC2",
                "region": "us-east-1",
                "name": "unauthorized-crypto-worker",
                "tags": json.dumps({"env": "test"}),
                "owner_tag": None,
                "public_access": 1,
                "idle_days": 42,
                "est_monthly_cost": 284.50,
                "created_at": (now - timedelta(days=95)).isoformat(),
                "is_flagged": 1,
                "scan_timestamp": now.isoformat(),
                "score": 92.4,
                "risk_bucket": "HIGH",
                "approval": {
                    "status": "PENDING",
                    "sre_name": None,
                    "action_taken": None,
                    "reason": None,
                    "slack_message_ts": "1710000001.000100"
                },
                "incident": {
                    "id": "INC-84920",
                    "status": "Pending Approval",
                    "trigger_source": "SecurityGroup 0.0.0.0/0 & CloudWatch Idle",
                    "runbook_generator": "template"
                }
            },
            # 2. High risk exposed S3 bucket
            {
                "id": "prod-customer-exports-backup-tmp",
                "type": "S3",
                "region": "global",
                "name": "prod-customer-exports-backup-tmp",
                "tags": json.dumps({"department": "sales"}),
                "owner_tag": None,
                "public_access": 1,
                "idle_days": 28,
                "est_monthly_cost": 45.20,
                "created_at": (now - timedelta(days=60)).isoformat(),
                "is_flagged": 1,
                "score": 87.8,
                "risk_bucket": "HIGH",
                "approval": {
                    "status": "APPROVED",
                    "sre_name": "sarah.chen",
                    "action_taken": "approved — whitelist / temporary data migration",
                    "reason": "Temporary sync approved until Friday maintenance window.",
                    "slack_message_ts": "1710000002.000200"
                },
                "incident": {
                    "id": "INC-84921",
                    "status": "Approved",
                    "trigger_source": "S3 Public Read ACL Policy",
                    "runbook_generator": "template"
                }
            },
            # 3. Medium risk idle RDS database
            {
                "id": "db-analytics-dev-legacy-v1",
                "type": "RDS",
                "region": "us-west-2",
                "name": "db-analytics-dev-legacy-v1",
                "tags": json.dumps({"owner": "josh", "project": "analytics"}),
                "owner_tag": "josh",
                "public_access": 0,
                "idle_days": 35,
                "est_monthly_cost": 178.00,
                "created_at": (now - timedelta(days=140)).isoformat(),
                "is_flagged": 1,
                "score": 58.6,
                "risk_bucket": "MEDIUM",
                "approval": {
                    "status": "SNOOZED",
                    "sre_name": "alex.m",
                    "action_taken": "snoozed alert for 24h grace period",
                    "reason": "Owner contacted to take final snapshot before teardown.",
                    "slack_message_ts": "1710000003.000300"
                },
                "incident": {
                    "id": "INC-84922",
                    "status": "Snoozed",
                    "trigger_source": "0 Active Database Connections for > 30 days",
                    "runbook_generator": "template"
                }
            },
            # 4. High risk exposed RDS instance
            {
                "id": "db-public-staging-postgres",
                "type": "RDS",
                "region": "eu-west-1",
                "name": "db-public-staging-postgres",
                "tags": json.dumps({"team": "frontend"}),
                "owner_tag": None,
                "public_access": 1,
                "idle_days": 18,
                "est_monthly_cost": 210.00,
                "created_at": (now - timedelta(days=45)).isoformat(),
                "is_flagged": 1,
                "score": 89.2,
                "risk_bucket": "HIGH",
                "approval": {
                    "status": "REJECTED",
                    "sre_name": "marcus.k",
                    "action_taken": "flagged rogue resource — quarantine scheduled",
                    "reason": "Direct public endpoint forbidden by company security policy.",
                    "slack_message_ts": "1710000004.000400"
                },
                "incident": {
                    "id": "INC-84923",
                    "status": "Rejected",
                    "trigger_source": "PubliclyAccessible=true with missing governance tags",
                    "runbook_generator": "template"
                }
            },
            # 5. Low risk flagged asset
            {
                "id": "i-0c1d2e3f4a5b6c7d8",
                "type": "EC2",
                "region": "us-east-1",
                "name": "ci-runner-ephemeral-4",
                "tags": json.dumps({"owner": "ci-bot", "environment": "staging"}),
                "owner_tag": "ci-bot",
                "public_access": 0,
                "idle_days": 16,
                "est_monthly_cost": 28.00,
                "created_at": (now - timedelta(days=20)).isoformat(),
                "is_flagged": 1,
                "score": 28.5,
                "risk_bucket": "LOW",
                "approval": {
                    "status": "RESOLVED",
                    "sre_name": "sarah.chen",
                    "action_taken": "auto-resolved by cleanup lambda",
                    "reason": "Instance stopped by automated auto-scaler.",
                    "slack_message_ts": None
                },
                "incident": {
                    "id": "INC-84924",
                    "status": "Resolved",
                    "trigger_source": "Missing project and team tags",
                    "runbook_generator": "template"
                }
            },
            # 6. Compliant production asset
            {
                "id": "i-0987654321fedcba0",
                "type": "EC2",
                "region": "us-east-1",
                "name": "core-api-gateway-prod-01",
                "tags": json.dumps({"owner": "platform", "team": "sre", "environment": "prod", "project": "api"}),
                "owner_tag": "platform",
                "public_access": 0,
                "idle_days": 0,
                "est_monthly_cost": 85.00,
                "created_at": (now - timedelta(days=220)).isoformat(),
                "is_flagged": 0,
                "score": 12.0,
                "risk_bucket": "SAFE",
                "approval": None,
                "incident": None
            },
            # 7. Compliant secure S3 bucket
            {
                "id": "company-immutable-audit-logs",
                "type": "S3",
                "region": "global",
                "name": "company-immutable-audit-logs",
                "tags": json.dumps({"owner": "compliance", "team": "security", "environment": "prod", "project": "audit"}),
                "owner_tag": "compliance",
                "public_access": 0,
                "idle_days": 0,
                "est_monthly_cost": 12.50,
                "created_at": (now - timedelta(days=365)).isoformat(),
                "is_flagged": 0,
                "score": 5.0,
                "risk_bucket": "SAFE",
                "approval": None,
                "incident": None
            }
        ]
        
        insert_resource = """
        INSERT OR REPLACE INTO resources (
            id, type, region, name, tags, owner_tag, public_access,
            idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        insert_risk = """
        INSERT OR REPLACE INTO risk_scores (
            resource_id, score, risk_bucket, model_version, explanation, scored_at
        ) VALUES (?, ?, ?, 'rf-v1', ?, ?)
        """
        
        insert_approval = """
        INSERT OR REPLACE INTO approvals (
            resource_id, sre_name, status, action_taken, reason, slack_message_ts, decided_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        insert_incident = """
        INSERT OR REPLACE INTO incidents (
            id, resource_id, type, region, account_id, trigger_source, score, risk_tier,
            dedupe_key, status, pipeline_status, detected_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        insert_runbook = """
        INSERT INTO incident_runbooks (
            incident_id, markdown, version, generator, github_url, created_at
        ) VALUES (?, ?, 1, ?, ?, ?)
        """
        
        account_id = "1234****9012"
        
        for item in mock_resources:
            conn.execute(insert_resource, (
                item["id"], item["type"], item["region"], item["name"],
                item["tags"], item["owner_tag"], item["public_access"],
                item["idle_days"], item["est_monthly_cost"], item["created_at"],
                item["is_flagged"], item.get("scan_timestamp", now.isoformat())
            ))
            scan_ts = item.get("scan_timestamp", now.isoformat())
            
            explanation = (
                f"Resource {item['name']} exhibits high vulnerability factors: public exposure "
                f"={bool(item['public_access'])}, dormant for {item['idle_days']} days, with ${item['est_monthly_cost']:.2f}/mo spend."
            )
            conn.execute(insert_risk, (
                item["id"], item["score"], item["risk_bucket"], explanation, scan_ts
            ))
            
            approval_id = None
            if item.get("approval"):
                app = item["approval"]
                decided_at = (now - timedelta(hours=2)).isoformat() if app["status"] != "PENDING" else None
                cur = conn.execute(insert_approval, (
                    item["id"], app["sre_name"], app["status"], app["action_taken"],
                    app["reason"], app["slack_message_ts"], decided_at
                ))
                approval_id = cur.lastrowid
                
                # Add sample comment and reminder for pending/snoozed items
                if app["status"] in ("PENDING", "SNOOZED"):
                    conn.execute("""
                        INSERT INTO comments (approval_id, author_name, comment_text, post_to_slack, created_at)
                        VALUES (?, 'sec-bot', 'Automated governance reminder dispatched to #cloud-governance channel.', 0, ?)
                    """, (approval_id, now.isoformat()))
                    
                    conn.execute("""
                        INSERT INTO reminders (approval_id, scheduled_time, note, post_to_slack, status, created_at)
                        VALUES (?, ?, 'Follow up with owner before scheduled quarantine', 0, 'PENDING', ?)
                    """, (approval_id, (now + timedelta(hours=4)).isoformat(), now.isoformat()))

            if item.get("incident"):
                inc = item["incident"]
                dedupe = generate_dedupe_key(account_id, item["region"], item["id"], inc["trigger_source"])
                pip_status = json.dumps({"detected": "ok", "runbook": "ok", "github": "ok", "slack": "ok"})
                
                conn.execute(insert_incident, (
                    inc["id"], item["id"], item["type"], item["region"], account_id,
                    inc["trigger_source"], item["score"], item["risk_bucket"], dedupe,
                    inc["status"], pip_status, item["created_at"], now.isoformat()
                ))
                
                # Sample runbook markdown
                sample_runbook = f"""# Incident Runbook: {inc['id']}

## 1. Incident Summary
- **Resource ID**: `{item['id']}`
- **Resource Name**: {item['name']}
- **Service Type**: {item['type']}
- **Region**: `{item['region']}`
- **AWS Account**: `{account_id}`
- **Risk Score**: **{item['score']}/100** ({item['risk_bucket']})
- **Detection Trigger**: {inc['trigger_source']}
- **Blast Radius**: High potential for unauthorized lateral movement or unmonitored egress.

## 2. Affected Configuration & Root Cause
- **Public Ingress**: {'Public IP / 0.0.0.0/0 exposed' if item['public_access'] else 'Private network only'}
- **Inactivity Period**: {item['idle_days']} consecutive idle days recorded via CloudWatch metrics.
- **Estimated Monthly Waste**: ${item['est_monthly_cost']:.2f}/month.
- **Missing Tags**: Missing organization baseline governance tags.

## 3. Impact Assessment
- **Security**: Public network boundary violation; vulnerable to unauthorized port probing.
- **Cost**: Incurring financial drain without recorded production workload.
- **Compliance**: Non-compliant with CIS AWS Foundations Benchmark.

## 4. Immediate Containment & Remediation Plan
Execute the following remediation command:
```bash
aws {item['type'].lower()} stop-instances --instance-ids {item['id']} --region {item['region'] if item['region'] != 'global' else 'us-east-1'}
```
*Rollback Note: Run `start-instances` if validated by project owner within 48 hours.*

## 5. Verification Steps
1. Verify instance state is stopped or isolated.
2. Confirm security group ingress rules do not contain `0.0.0.0/0`.
3. Check CloudWatch billing alarm trends.

## 6. Future Prevention & Safety Guardrails
- Deploy AWS Service Control Policy (SCP) restricting unapproved internet gateways.
- Enforce AWS Config rule `required-tags` for automated quarantine.
- Configure AWS Budgets zero-utilization notifications.

---
*Metadata: Incident ID: {inc['id']} | Generator: template | Generated: {now.isoformat()}*
"""
                conn.execute(insert_runbook, (
                    inc["id"], sample_runbook, inc["runbook_generator"],
                    f"https://github.com/org/runbooks/blob/main/runbooks/2026/{inc['id']}_{item['id']}.md",
                    now.isoformat()
                ))
                
        # Insert initial account snapshot
        snapshot_metrics = {
            "account_id": account_id,
            "total_resources": len(mock_resources),
            "flagged_count": sum(1 for m in mock_resources if m["is_flagged"]),
            "high_risk_count": sum(1 for m in mock_resources if m["risk_bucket"] == "HIGH"),
            "monthly_spend": sum(m["est_monthly_cost"] for m in mock_resources),
            "regions_scanned": ["us-east-1", "us-west-2", "eu-west-1", "global"],
            "regions_failed": [],
            "last_scan_duration_sec": 4.12
        }
        conn.execute("""
            INSERT INTO account_snapshots (account_id, regions_scanned, regions_failed, metrics_json, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (
            account_id, json.dumps(["us-east-1", "us-west-2", "eu-west-1"]),
            json.dumps([]), json.dumps(snapshot_metrics), now.isoformat()
        ))
        
        conn.commit()
    print(f"Successfully injected {len(mock_resources)} diverse resources & incident runbooks into {target_db}!")

if __name__ == "__main__":
    inject()
