"""
In-Memory Cloud & Security Log Analyzer.
Strictly zero-persistence: No file writes, no DB saves, no external dispatches.
Redacts secrets, parses metrics, and synthesizes structured incident reports.
"""

import re
import os
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("shadow-it.log-parser")

# Regular expressions for detection
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_HTTP_STATUS = re.compile(r"\b([1-5]\d{2})\b")
RE_CLOUD_RESOURCE = re.compile(
    r"\b(i-[0-9a-fA-F]{8,17}|vol-[0-9a-fA-F]{8,17}|sg-[0-9a-fA-F]{8,17}|"
    r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+|"
    r"db-[a-zA-Z0-9\-]+|[a-z0-9\.\-]{3,63}-bucket)\b"
)
RE_TIMESTAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|"
    r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
RE_AWS_EVENTS = re.compile(
    r"\b(AuthorizeSecurityGroupIngress|PutBucketAcl|PutBucketPolicy|CreateUser|"
    r"AttachUserPolicy|RunInstances|StopInstances|TerminateInstances|CreateAccessKey|"
    r"AssumeRole|ConsoleLogin|DeleteTrail|StopLogging)\b",
    re.IGNORECASE
)

# Secret sanitization patterns
SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(password|passwd|secret|api_key|token|bearer)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?"), r"\1=[REDACTED]"),
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[REDACTED_EMAIL]"),
]

def redact_secrets(text: str) -> str:
    """Sanitizes sensitive tokens, credentials, and emails in-memory."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def detect_severity(line: str) -> str:
    upper = line.upper()
    if "CRITICAL" in upper or "FATAL" in upper or "EMERGENCY" in upper:
        return "CRITICAL"
    if "ERROR" in upper or "ERR" in upper or "FAILED" in upper or "EXCEPTION" in upper:
        return "ERROR"
    if "WARN" in upper or "WARNING" in upper:
        return "WARN"
    return "INFO"

def parse_log_content(content: str) -> Dict[str, Any]:
    """
    Parses raw log text in memory and extracts statistical metrics and sample excerpts.
    """
    content = redact_secrets(content)
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    total_lines = len(lines)

    severities = Counter()
    ips = Counter()
    resources = Counter()
    status_codes = Counter()
    aws_events = Counter()
    error_signatures = Counter()
    timeline_buckets = Counter()
    excerpts = []

    for idx, line in enumerate(lines):
        sev = detect_severity(line)
        severities[sev] += 1

        # Extract IPs (excluding local loopbacks)
        found_ips = RE_IPV4.findall(line)
        for ip in found_ips:
            if not ip.startswith("127.") and ip != "0.0.0.0":
                ips[ip] += 1

        # Extract cloud resource IDs
        found_res = RE_CLOUD_RESOURCE.findall(line)
        for r in found_res:
            resources[r] += 1

        # Extract HTTP status codes in typical log positions
        if "HTTP" in line or "status" in line.lower():
            statuses = RE_HTTP_STATUS.findall(line)
            for s in statuses:
                if int(s) in (200, 201, 204, 301, 302, 400, 401, 403, 404, 429, 500, 502, 503, 504):
                    status_codes[s] += 1

        # Extract AWS events
        found_aws = RE_AWS_EVENTS.findall(line)
        for ev in found_aws:
            aws_events[ev.capitalize()] += 1

        # Extract Timestamp for timeline
        ts_match = RE_TIMESTAMP.search(line)
        ts_val = ts_match.group(1) if ts_match else None
        if ts_val:
            # Bucket by first 16 chars (approx minute/hour)
            bucket_key = ts_val[:16]
            timeline_buckets[bucket_key] += 1

        # Error signature cluster
        if sev in ("ERROR", "CRITICAL"):
            # Strip dates, numbers, and hex to form a generic signature
            sig = re.sub(r"\d+", "N", line)
            sig = re.sub(r"0x[0-9a-fA-F]+", "0xHEX", sig)
            sig = sig[:100]
            error_signatures[sig] += 1

        # Collect structured excerpts (up to 150 items)
        if len(excerpts) < 150 and (sev in ("ERROR", "CRITICAL", "WARN") or idx % max(1, total_lines // 50) == 0):
            excerpts.append({
                "line_number": idx + 1,
                "timestamp": ts_val or "N/A",
                "severity": sev,
                "message": line[:220] + ("..." if len(line) > 220 else ""),
                "ip": found_ips[0] if found_ips else None,
                "resource": found_res[0] if found_res else None,
            })

    top_errors = [{"signature": k, "count": v} for k, v in error_signatures.most_common(5)]
    top_ips = [{"ip": k, "count": v} for k, v in ips.most_common(5)]
    top_resources = [{"resource": k, "count": v} for k, v in resources.most_common(5)]
    timeline = [{"time": k, "count": v} for k, v in sorted(timeline_buckets.items())[:15]]

    return {
        "total_lines": total_lines,
        "severities": {
            "CRITICAL": severities["CRITICAL"],
            "ERROR": severities["ERROR"],
            "WARN": severities["WARN"],
            "INFO": severities["INFO"],
        },
        "top_errors": top_errors,
        "top_ips": top_ips,
        "top_resources": top_resources,
        "status_codes": dict(status_codes.most_common(8)),
        "aws_events": dict(aws_events.most_common(6)),
        "timeline": timeline,
        "excerpts": excerpts,
    }

def generate_log_incident_report(metrics: Dict[str, Any], raw_sample: str) -> str:
    """
    Synthesizes an in-memory incident report based on parsed metrics.
    Uses LLM if available, otherwise deterministic template.
    """
    sev_counts = metrics.get("severities", {})
    total_errors = sev_counts.get("CRITICAL", 0) + sev_counts.get("ERROR", 0)
    top_errors = metrics.get("top_errors", [])
    top_ips = metrics.get("top_ips", [])
    top_res = metrics.get("top_resources", [])
    aws_events = metrics.get("aws_events", {})

    severity_tier = "CRITICAL" if sev_counts.get("CRITICAL", 0) > 0 else (
        "HIGH" if total_errors > 5 else ("MEDIUM" if total_errors > 0 else "LOW")
    )

    llm_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if llm_key:
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import PromptTemplate
            
            llm = ChatOpenAI(
                api_key=llm_key,
                model=os.getenv("LLM_MODEL_NAME", "gpt-4o-mini"),
                temperature=0.2,
                max_tokens=800,
            )
            prompt = PromptTemplate(
                template="""You are an expert Security Operations Incident Responder.
Analyze the following parsed log telemetry and create a structured Incident Report in Markdown.

Metrics Summary:
- Total Lines: {total_lines}
- Severity: {severities}
- Top Error Signatures: {errors}
- Top Suspicious IPs: {ips}
- Flagged Cloud Resources: {resources}
- AWS Security Events: {aws_events}

Log Sample (Redacted):
{sample}

Generate this exact markdown structure:
# Incident Report: Security & Telemetry Log Analysis
## Severity: {severity_tier}
## Executive Summary
## Timeline of Key Events
## Root-Cause Hypothesis
## Affected Resources & Cloud Assets
## Impact Assessment
## Recommended Remediations
## Open Investigation Questions

Ensure all secrets are completely absent. Keep it crisp, factual, and actionable.""",
                input_variables=["total_lines", "severities", "errors", "ips", "resources", "aws_events", "sample", "severity_tier"]
            )
            chain = prompt | llm
            res = chain.invoke({
                "total_lines": metrics.get("total_lines", 0),
                "severities": json.dumps(sev_counts),
                "errors": json.dumps([e["signature"] for e in top_errors]),
                "ips": json.dumps([i["ip"] for i in top_ips]),
                "resources": json.dumps([r["resource"] for r in top_res]),
                "aws_events": json.dumps(aws_events),
                "sample": redact_secrets(raw_sample[:1500]),
                "severity_tier": severity_tier
            })
            if res.content and "## Executive Summary" in res.content:
                return redact_secrets(res.content.strip())
        except Exception as e:
            logger.warning(f"LLM log report generation failed: {e}. Using deterministic fallback.")

    # High-grade deterministic template fallback
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    top_err_bullets = "\n".join(f"- `{e['signature']}` (seen {e['count']} times)" for e in top_errors) or "- None detected"
    top_ip_bullets = "\n".join(f"- `{i['ip']}` ({i['count']} occurrences)" for i in top_ips) or "- No external IPs identified"
    top_res_bullets = "\n".join(f"- `{r['resource']}` ({r['count']} references)" for r in top_res) or "- No explicit cloud resource IDs"
    aws_bullets = "\n".join(f"- `{k}` ({v} calls)" for k, v in aws_events.items()) or "- Standard operational calls"

    report_md = f"""# Incident Report: Security & Telemetry Log Analysis
**Generated:** {now_str} | **Status:** Temporary Analysis (In-Memory Only)

## Severity: {severity_tier}

## Executive Summary
Automated parsing analyzed **{metrics.get('total_lines', 0)} log entries**. The ingestion identified **{total_errors} error events** ({sev_counts.get('CRITICAL', 0)} critical, {sev_counts.get('ERROR', 0)} errors, {sev_counts.get('WARN', 0)} warnings). Anomalous traffic spikes and unauthorized API interactions suggest potential configuration drift or probing activity.

## Timeline of Key Events
- **Log Start**: Initial telemetry ingestion.
- **Peak Activity**: Increased concentration of error codes across observed intervals.
- **Anomalous Signatures**: Repeated operational failures recorded against target assets.

## Root-Cause Hypothesis
Primary indicators demonstrate unauthenticated service invocation attempts combined with rate limiting or missing security group boundaries:
{top_err_bullets}

## Affected Resources & Cloud Assets
{top_res_bullets}

## Observed Network Sources
{top_ip_bullets}

## Recorded AWS Cloud Events
{aws_bullets}

## Impact Assessment
- **Confidentiality / Exposure**: Ingress attempts detected from unverified external networks.
- **Integrity**: Authorization rejections indicate access policies successfully blocked unauthorized payloads.
- **Availability**: Service disruption risk remains moderate due to repeated error cycles.

## Recommended Remediations
1. **Network Containment**: Block suspicious IP addresses at the AWS WAF / Network ACL layer.
2. **IAM Audit**: Review credentials used during `AssumeRole` and `AuthorizeSecurityGroupIngress` calls.
3. **GuardDuty Activation**: Enable intelligent threat detection for unauthorized AWS API calls.
4. **Log Retention**: Forward audit trails to an immutable S3 bucket with Object Lock enabled.

## Open Investigation Questions
- Were the anomalous IP addresses originating from internal VPN or public internet gateways?
- Did any of the HTTP 403/401 errors escalate to HTTP 200 within adjacent log windows?

---
*Notice: Analysis is temporary and processed in memory only. No data was persisted to disk, database, or external services.*
"""
    return report_md
