"""
Incident Runbook & GenAI Report Generator for Shadow IT Detection.
Generates structured Markdown runbooks with:
1. Incident summary
2. Affected resources & root cause configuration
3. Impact assessment
4. Containment & Remediation plan (AWS CLI commands)
5. Verification steps
6. Future safety & guardrails
7. Timeline & status history
8. Metadata footer
Supports OpenAI/standard LLM providers with high-grade deterministic template fallback.
"""

import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

logger = logging.getLogger("shadow-it.runbook-generator")

def redact_sensitive_info(text: str) -> str:
    """Redacts potential AWS keys, bearer tokens, passwords, and sensitive emails."""
    if not text:
        return ""
    # Redact AWS Access Key IDs
    text = re.sub(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b", "[REDACTED_AWS_KEY]", text)
    # Redact secret key patterns or high entropy tokens
    text = re.sub(r"(?i)(password|secret|bearer|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?", r"\1: [REDACTED]", text)
    # Redact emails
    text = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]", text)
    return text

def build_deterministic_runbook(
    incident_id: str,
    resource: Dict[str, Any],
    risk_score: float,
    risk_tier: str,
    trigger_source: str,
    account_id: str = "1234****9012",
    region: str = "us-east-1",
    generator_label: str = "template"
) -> str:
    """Generates a professional, comprehensive Markdown runbook using standard cloud security templates."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    res_id = resource.get("id", "res-unknown")
    res_name = resource.get("name", res_id)
    res_type = resource.get("type", "EC2").upper()
    cost = float(resource.get("est_monthly_cost", 0.0))
    idle_days = int(resource.get("idle_days", 0))
    public_access = bool(resource.get("public_access", False))
    
    # Missing tags calculation
    tags_raw = resource.get("tags", "{}")
    tags_dict = {}
    if isinstance(tags_raw, dict):
        tags_dict = tags_raw
    else:
        try:
            tags_dict = json.loads(tags_raw) if tags_raw else {}
        except Exception:
            tags_dict = {}
    present_tags = {k.lower() for k in tags_dict.keys()}
    req_tags = ["owner", "team", "environment", "project"]
    missing_tags = [t for t in req_tags if t not in present_tags]

    # CLI commands per type
    if res_type == "EC2":
        remediation_cmd = (
            f"# 1. Isolate network via quarantine security group\n"
            f"aws ec2 modify-instance-attribute --instance-id {res_id} --groups sg-quarantine-default --region {region}\n\n"
            f"# 2. Stop rogue instance to eliminate financial waste\n"
            f"aws ec2 stop-instances --instance-ids {res_id} --region {region}"
        )
        verification_cmd = f"aws ec2 describe-instances --instance-ids {res_id} --query 'Reservations[*].Instances[*].State.Name' --region {region}"
    elif res_type == "S3":
        remediation_cmd = (
            f"# 1. Enable Account & Bucket Level S3 Block Public Access\n"
            f"aws s3api put-public-access-block --bucket {res_id} --public-access-block-configuration "
            f"\"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"\n\n"
            f"# 2. Remove permissive public bucket policies\n"
            f"aws s3api delete-bucket-policy --bucket {res_id}"
        )
        verification_cmd = f"aws s3api get-public-access-block --bucket {res_id}"
    elif res_type == "RDS":
        remediation_cmd = (
            f"# 1. Take safety snapshot before containment\n"
            f"aws rds create-db-snapshot --db-instance-identifier {res_id} --db-snapshot-identifier {res_id}-quarantine-snap --region {region}\n\n"
            f"# 2. Modify to disable public accessibility\n"
            f"aws rds modify-db-instance --db-instance-identifier {res_id} --no-publicly-accessible --apply-immediately --region {region}"
        )
        verification_cmd = f"aws rds describe-db-instances --db-instance-identifier {res_id} --query 'DBInstances[*].PubliclyAccessible' --region {region}"
    else:
        remediation_cmd = f"# Review and quarantine resource\naws resourcegroupstaggingapi get-resources --resource-arn-list {res_id}"
        verification_cmd = f"aws resourcegroupstaggingapi get-resources --resource-arn-list {res_id}"

    runbook_md = f"""# Incident Runbook: {incident_id}

## 1. Incident Summary
- **Incident ID**: `{incident_id}`
- **Resource ID**: `{res_id}`
- **Resource Name**: {res_name}
- **Service Type**: **{res_type}**
- **Region**: `{region}`
- **AWS Account**: `{account_id}`
- **Risk Evaluation**: **{risk_score}/100** ({risk_tier} RISK)
- **Detection Trigger**: {trigger_source}
- **Blast Radius**: Critical exposure risk. The asset violates cloud boundary segmentation with potential for unauthorized lateral ingress or unmonitored data exfiltration.

## 2. Affected Configuration & Root Cause Analysis
The following specific configuration drivers saturated the risk engine threshold:
- **Public Network Access**: {'EXPOSED (0.0.0.0/0 ingress detected)' if public_access else 'Enclosed in VPC'}
- **Dormancy & Idle Period**: {idle_days} consecutive days with negligible CloudWatch utilization.
- **Monthly Runaway Cost**: ${cost:.2f}/month wasted on unmaintained infrastructure.
- **Missing Governance Tags**: {', '.join(missing_tags) if missing_tags else 'None (tags compliant)'}.

## 3. Impact Assessment
- **Security Impact**: Threat actors can scan and access unauthenticated service endpoints.
- **Financial Impact**: Estimated direct annual waste of **${cost * 12:.2f}** if left unmanaged.
- **Compliance Impact**: Violates SOC2, ISO 27001, and CIS AWS Foundations Benchmark section 2.1.

## 4. Immediate Containment & Remediation Plan
Follow this sequential execution plan:
```bash
{remediation_cmd}
```
*Rollback Note: If verified as legitimate production asset by team lead, revert state within 48 hours.*

## 5. Verification Steps
Execute this verification probe to ensure exposure is neutralized:
```bash
{verification_cmd}
```
Ensure the response confirms containment and public network routes have been revoked.

## 6. Future Prevention & Safety Guardrails
To prevent reoccurrence across the AWS organization:
1. **Service Control Policy (SCP)**: Deny creation of default VPCs and public IP attachments in non-DMZ subnets.
2. **AWS Config Rules**: Deploy managed rule `INCOMING_SSH_DISABLED` and `S3_BUCKET_PUBLIC_READ_PROHIBITED`.
3. **IaC Linting**: Enforce Terraform/CloudFormation pre-commit checks blocking wildcard security groups.
4. **Billing Alarms**: Configure AWS Budgets to alert on unattached or idle resources older than 7 days.

## 7. Timeline & Status History
- **{now_iso}**: Detected by automated Shadow IT multi-region scanner.
- **{now_iso}**: Risk score computed as {risk_score} ({risk_tier}); automated incident and runbook published.
- **Current Status**: **Open / Pending SRE Review**

---
*Metadata Footer: Incident ID: {incident_id} | AWS Account: {account_id} | Region: {region} | Generated: {now_iso} | Generator: {generator_label}*
"""
    return runbook_md

def generate_runbook_with_llm_or_fallback(
    incident_id: str,
    resource: Dict[str, Any],
    risk_score: float,
    risk_tier: str,
    trigger_source: str,
    account_id: str = "1234****9012",
    region: str = "us-east-1"
) -> Tuple[str, str]:
    """
    Attempts to generate an executive-grade runbook using the configured LLM provider.
    Gracefully falls back to deterministic template generation if LLM is unavailable or fails.
    Returns: (runbook_markdown, generator_label)
    """
    llm_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    generator_label = "template"
    
    if llm_key:
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import PromptTemplate

            base_url = os.getenv("LLM_BASE_URL")
            model_name = os.getenv("LLM_MODEL_NAME", "gpt-4o-mini")
            
            kwargs = {
                "api_key": llm_key,
                "model": model_name,
                "temperature": 0.2,
                "max_tokens": 850,
            }
            if base_url:
                kwargs["base_url"] = base_url

            llm = ChatOpenAI(**kwargs)
            prompt = PromptTemplate(
                template="""You are a Principal Cloud Security SRE. Create a comprehensive, production-grade Markdown incident runbook for this flagged rogue cloud resource.

Resource Details:
- ID: {res_id}
- Type: {res_type}
- Name: {res_name}
- Region: {region}
- Public Access: {public_access}
- Idle Days: {idle_days}
- Monthly Waste: ${cost}
- Risk Score: {score}/100 ({tier})
- Detection Trigger: {trigger}

Include these exact numbered markdown sections:
## 1. Incident Summary
## 2. Affected Configuration & Root Cause Analysis
## 3. Impact Assessment
## 4. Immediate Containment & Remediation Plan (with exact executable AWS CLI commands)
## 5. Verification Steps
## 6. Future Prevention & Safety Guardrails
## 7. Timeline & Status History

Do not include secrets or keys. End with:
---
*Metadata Footer: Incident ID: {inc_id} | AWS Account: {account_id} | Region: {region} | Generator: llm*
""",
                input_variables=["res_id", "res_type", "res_name", "region", "public_access", "idle_days", "cost", "score", "tier", "trigger", "inc_id", "account_id"]
            )
            chain = prompt | llm
            res_id = resource.get("id", "res-unknown")
            output = chain.invoke({
                "res_id": res_id,
                "res_type": resource.get("type", "EC2"),
                "res_name": resource.get("name", res_id),
                "region": region,
                "public_access": "YES" if resource.get("public_access") else "NO",
                "idle_days": resource.get("idle_days", 0),
                "cost": resource.get("est_monthly_cost", 0.0),
                "score": risk_score,
                "tier": risk_tier,
                "trigger": trigger_source,
                "inc_id": incident_id,
                "account_id": account_id,
            })
            content = output.content.strip()
            if content and "## 1. Incident Summary" in content:
                return redact_sensitive_info(content), "llm"
        except Exception as e:
            logger.warning(f"LLM runbook generation failed ({e}); switching to deterministic template fallback.")

    # High-grade deterministic template
    runbook_md = build_deterministic_runbook(
        incident_id=incident_id,
        resource=resource,
        risk_score=risk_score,
        risk_tier=risk_tier,
        trigger_source=trigger_source,
        account_id=account_id,
        region=region,
        generator_label="template"
    )
    return redact_sensitive_info(runbook_md), "template"
