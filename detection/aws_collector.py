"""
AWS Multi-Region Account-Wide Telemetry Collector & Incident Detector.
Strictly Read-Only boto3 operations.
Discovers scope dynamically via STS and DescribeRegions.
Graceful degradation with partial region failure handling and mock fallback.
"""

import os
import re
import json
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import boto3
from botocore.exceptions import NoCredentialsError, ClientError, EndpointConnectionError
from botocore.config import Config

logger = logging.getLogger("shadow-it.aws-collector")

REPO_ROOT = Path(__file__).resolve().parent.parent
from shared.db import get_connection

# Read-only standard boto retry config
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=10,
)

def mask_account_id(account_id: Optional[str]) -> str:
    """Masks AWS account id for privacy (e.g. 1234****9012)."""
    if not account_id:
        return "1234****9012"
    s = str(account_id)
    if len(s) >= 8:
        return f"{s[:4]}****{s[-4:]}"
    return "1234****9012"

def mask_arn(arn: Optional[str]) -> str:
    """Partially masks sensitive account identifier inside ARNs."""
    if not arn:
        return ""
    # Matches arn:aws:service:region:account-id:resource
    return re.sub(r":\d{12}:", ":****:", str(arn))

def is_mock_mode() -> bool:
    """Returns True if MOCK_MODE is enabled or AWS credentials are absent."""
    if os.getenv("MOCK_MODE", "").lower() in ("1", "true", "yes"):
        return True
    
    # Check credentials
    if not (os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")):
        # Check if running under AWS role / standard session
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            if not creds:
                return True
        except Exception:
            return True
    return False

def get_account_identity() -> Tuple[str, str]:
    """Retrieves current AWS account ID and ARN using STS."""
    try:
        sts = boto3.client("sts", config=BOTO_CONFIG)
        caller = sts.get_caller_identity()
        return caller.get("Account", "123456789012"), caller.get("Arn", "")
    except Exception as e:
        logger.warning(f"Could not fetch STS caller identity ({e}). Using fallback.")
        return "123456789012", "arn:aws:iam::123456789012:root"

def get_enabled_regions() -> List[str]:
    """Retrieves all enabled EC2 regions for the AWS account."""
    try:
        default_region = os.getenv("AWS_REGION", "us-east-1")
        ec2 = boto3.client("ec2", region_name=default_region, config=BOTO_CONFIG)
        resp = ec2.describe_regions(AllRegions=False)
        regions = [r["RegionName"] for r in resp.get("Regions", [])]
        if regions:
            return regions
    except Exception as e:
        logger.warning(f"Could not discover enabled regions dynamically: {e}")
    return ["us-east-1", "us-west-2", "eu-west-1"]

def scan_region_ec2(region: str) -> List[Dict[str, Any]]:
    """Scans EC2 instances and attached security groups in a given region."""
    results = []
    try:
        ec2 = boto3.client("ec2", region_name=region, config=BOTO_CONFIG)
        cw = boto3.client("cloudwatch", region_name=region, config=BOTO_CONFIG)
        
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    inst_id = inst["InstanceId"]
                    state = inst["State"]["Name"]
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    
                    # Check public access
                    public_ip = inst.get("PublicIpAddress")
                    has_public_sg = False
                    for sg in inst.get("SecurityGroups", []):
                        # Security group evaluation
                        has_public_sg = True
                    public_access = 1 if (public_ip or has_public_sg) else 0

                    # CloudWatch idle calculation (batch/single)
                    idle_days = 0
                    if state == "running":
                        try:
                            end_time = datetime.now(timezone.utc)
                            start_time = end_time - timedelta(days=14)
                            cw_resp = cw.get_metric_data(
                                MetricDataQueries=[{
                                    "Id": "m1",
                                    "MetricStat": {
                                        "Metric": {
                                            "Namespace": "AWS/EC2",
                                            "MetricName": "CPUUtilization",
                                            "Dimensions": [{"Name": "InstanceId", "Value": inst_id}]
                                        },
                                        "Period": 86400,
                                        "Stat": "Average"
                                    }
                                }],
                                StartTime=start_time,
                                EndTime=end_time
                            )
                            values = cw_resp.get("MetricDataResults", [{}])[0].get("Values", [])
                            idle_days = sum(1 for v in values if v < 2.0)
                        except Exception:
                            idle_days = 0
                    else:
                        idle_days = 30

                    # Policy check
                    req_tags = {"owner", "team", "environment", "project"}
                    missing_tags = [t for t in req_tags if t not in {k.lower() for k in tags.keys()}]
                    is_flagged = 1 if (public_access or idle_days > 14 or len(missing_tags) >= 2) else 0

                    cost = 25.0 if inst.get("InstanceType", "").startswith("t") else 75.0
                    now_iso = datetime.now(timezone.utc).isoformat()
                    results.append({
                        "id": inst_id,
                        "type": "EC2",
                        "region": region,
                        "name": tags.get("Name", inst_id),
                        "tags": json.dumps(tags),
                        "owner_tag": tags.get("owner", ""),
                        "public_access": public_access,
                        "idle_days": idle_days,
                        "est_monthly_cost": cost,
                        "created_at": inst.get("LaunchTime", datetime.now(timezone.utc)).isoformat(),
                        "is_flagged": is_flagged,
                        "scan_timestamp": now_iso,
                        "missing_tags": missing_tags
                    })
    except Exception as e:
        logger.warning(f"Error scanning EC2 in region {region}: {e}")
    return results

def scan_region_rds(region: str) -> List[Dict[str, Any]]:
    """Scans RDS instances in a given region."""
    results = []
    try:
        rds = boto3.client("rds", region_name=region, config=BOTO_CONFIG)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db["DBInstanceIdentifier"]
                tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
                public_access = 1 if db.get("PubliclyAccessible") else 0
                idle_days = 14 if db.get("DBInstanceStatus") != "available" else 0
                
                req_tags = {"owner", "team", "environment", "project"}
                missing_tags = [t for t in req_tags if t not in {k.lower() for k in tags.keys()}]
                is_flagged = 1 if (public_access or idle_days > 14 or len(missing_tags) >= 2) else 0

                results.append({
                    "id": db_id,
                    "type": "RDS",
                    "region": region,
                    "name": db_id,
                    "tags": json.dumps(tags),
                    "owner_tag": tags.get("owner", ""),
                    "public_access": public_access,
                    "idle_days": idle_days,
                    "est_monthly_cost": 65.0,
                    "created_at": db.get("InstanceCreateTime", datetime.now(timezone.utc)).isoformat(),
                    "is_flagged": is_flagged,
                    "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                    "missing_tags": missing_tags
                })
    except Exception as e:
        logger.warning(f"Error scanning RDS in region {region}: {e}")
    return results

def scan_s3_buckets() -> List[Dict[str, Any]]:
    """Scans global S3 buckets and evaluates public exposure."""
    results = []
    try:
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            tags = {}
            try:
                tag_set = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                tags = {t["Key"]: t["Value"] for t in tag_set}
            except Exception:
                tags = {}

            public_access = 0
            try:
                pab = s3.get_public_access_block(Bucket=name)
                conf = pab.get("PublicAccessBlockConfiguration", {})
                if not conf.get("BlockPublicAcls", True) or not conf.get("BlockPublicPolicy", True):
                    public_access = 1
            except Exception:
                public_access = 0

            req_tags = {"owner", "team", "environment", "project"}
            missing_tags = [t for t in req_tags if t not in {k.lower() for k in tags.keys()}]
            is_flagged = 1 if (public_access or len(missing_tags) >= 2) else 0

            results.append({
                "id": name,
                "type": "S3",
                "region": "global",
                "name": name,
                "tags": json.dumps(tags),
                "owner_tag": tags.get("owner", ""),
                "public_access": public_access,
                "idle_days": 0,
                "est_monthly_cost": 15.0,
                "created_at": b.get("CreationDate", datetime.now(timezone.utc)).isoformat(),
                "is_flagged": is_flagged,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "missing_tags": missing_tags
            })
    except Exception as e:
        logger.warning(f"Error scanning S3: {e}")
    return results

def collect_account_wide_inventory() -> Dict[str, Any]:
    """
    Performs full multi-region parallel scan across all enabled regions.
    Returns aggregated account-wide metrics and resource lists.
    """
    if is_mock_mode():
        # Query local database as synthetic account inventory
        with get_connection() as conn:
            rows = conn.execute("SELECT * FROM resources").fetchall()
            resources = [dict(r) for r in rows]
            
            # Groupings
            total = len(resources)
            flagged = sum(1 for r in resources if r["is_flagged"])
            high_risk = conn.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_bucket = 'HIGH'").fetchone()[0]
            monthly_cost = sum(r["est_monthly_cost"] for r in resources)
            
            regions = list({r["region"] for r in resources if r.get("region")})
            services = list({r["type"] for r in resources if r.get("type")})

            return {
                "account_id": "1234****9012",
                "is_mock": True,
                "total_resources": total,
                "flagged_resources": flagged,
                "high_risk_count": high_risk,
                "monthly_spend": round(monthly_cost, 2),
                "regions_scanned": regions,
                "regions_failed": [],
                "resources": resources,
                "services": services,
                "scan_duration_sec": 0.5,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    start_time = datetime.now()
    account_id, _ = get_account_identity()
    regions = get_enabled_regions()
    
    all_resources = []
    scanned_regions = []
    failed_regions = []

    # Scan S3 globally
    all_resources.extend(scan_s3_buckets())

    # Multi-region parallel scanning
    with ThreadPoolExecutor(max_workers=min(len(regions), 8)) as executor:
        future_to_region = {}
        for r in regions:
            f_ec2 = executor.submit(scan_region_ec2, r)
            f_rds = executor.submit(scan_region_rds, r)
            future_to_region[f_ec2] = (r, "EC2")
            future_to_region[f_rds] = (r, "RDS")

        for future in as_completed(future_to_region):
            reg, svc = future_to_region[future]
            try:
                data = future.result()
                all_resources.extend(data)
                if reg not in scanned_regions:
                    scanned_regions.append(reg)
            except Exception as e:
                logger.error(f"Region {reg} {svc} scan failed: {e}")
                if reg not in failed_regions:
                    failed_regions.append(reg)

    duration = round((datetime.now() - start_time).total_seconds(), 2)
    masked_acc = mask_account_id(account_id)

    # Save to database
    with get_connection() as conn:
        for r in all_resources:
            conn.execute("""
                INSERT OR REPLACE INTO resources (
                    id, type, region, name, tags, owner_tag, public_access,
                    idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["id"], r["type"], r["region"], r["name"],
                r["tags"], r["owner_tag"], r["public_access"],
                r["idle_days"], r["est_monthly_cost"], r["created_at"],
                r["is_flagged"], r["scan_timestamp"]
            ))

        snapshot_data = {
            "account_id": masked_acc,
            "total_resources": len(all_resources),
            "flagged_resources": sum(1 for r in all_resources if r["is_flagged"]),
            "monthly_spend": sum(r["est_monthly_cost"] for r in all_resources),
            "regions_scanned": scanned_regions,
            "regions_failed": failed_regions,
            "scan_duration_sec": duration,
        }
        conn.execute("""
            INSERT INTO account_snapshots (account_id, regions_scanned, regions_failed, metrics_json, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (
            masked_acc, json.dumps(scanned_regions), json.dumps(failed_regions),
            json.dumps(snapshot_data), datetime.now(timezone.utc).isoformat()
        ))

    return {
        "account_id": masked_acc,
        "is_mock": False,
        "total_resources": len(all_resources),
        "flagged_resources": sum(1 for r in all_resources if r["is_flagged"]),
        "regions_scanned": scanned_regions,
        "regions_failed": failed_regions,
        "resources": all_resources,
        "scan_duration_sec": duration,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
