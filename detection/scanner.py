#Cloud Detection Module

import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from botocore.config import Config
import yaml
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.db import get_connection

POLICY_PATH = SCRIPT_DIR / "policy.yaml"


def load_policy():
    if not POLICY_PATH.exists():
        print(f"Policy file not found at {POLICY_PATH}")
        sys.exit(1)
    with open(POLICY_PATH, "r") as f:
        return yaml.safe_load(f)


def extract_tags(tag_list):
    """Convert AWS tag list [{'Key': 'x', 'Value': 'y'}] to a dict with sanitization."""
    if not tag_list:
        return {}
        
    sanitized = {}
    for t in tag_list:
        # Sanitize: limit length to prevent DB overflow / JSON parsing bombs
        key = str(t['Key'])[:128]
        val = str(t['Value'])[:256]
        sanitized[key] = val
    return sanitized


def evaluate_policy(tags_dict, public_access, idle_days, policy):
    # Applies the compliance check.
    #Returns True if flagged as rogue (violates policy).
    
    required_tags = policy.get("required_tags", [])
    thresholds = policy.get("thresholds", {})
    
    # Check for missing tags
    tag_keys = {k.lower() for k in tags_dict.keys()}
    for req_tag in required_tags:
        if req_tag.lower() not in tag_keys:
            return True  # Missing required tag
            
    # Check for public access violation
    if public_access and not thresholds.get("allow_public_access", False):
        return True
        
    # Check for idle days violation
    max_idle = thresholds.get("max_idle_days", 14)
    if idle_days > max_idle:
        return True
        
    return False


def get_ec2_idle_days(cloudwatch, inst_id, max_days=30):
    """Query CloudWatch to determine how many consecutive days an EC2 instance was < 2% CPU."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=max_days)
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': inst_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Maximum']
        )
        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return 0
        datapoints.sort(key=lambda x: x['Timestamp'], reverse=True)
        idle_count = 0
        for dp in datapoints:
            if dp['Maximum'] < 2.0:
                idle_count += 1
            else:
                break
        return idle_count
    except ClientError as e:
        print(f"CloudWatch error for EC2 {inst_id}: {e}")
        return 0


def get_rds_idle_days(cloudwatch, db_id, max_days=14):
    """Query CloudWatch to determine how many consecutive days an RDS instance had 0 connections."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=max_days)
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='DatabaseConnections',
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Maximum']
        )
        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return 0
        datapoints.sort(key=lambda x: x['Timestamp'], reverse=True)
        idle_count = 0
        for dp in datapoints:
            if dp['Maximum'] <= 0:
                idle_count += 1
            else:
                break
        return idle_count
    except ClientError as e:
        print(f"CloudWatch error for RDS {db_id}: {e}")
        return 0


def scan_ec2(policy, scan_ts):
    records = []
    
    # Mitigation for API Rate Limiting (Denial of Service)
    boto_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
    
    try:
        aws_region = os.getenv("AWS_REGION", "us-east-1")
        ec2 = boto3.client('ec2', region_name=aws_region, config=boto_config)
        cloudwatch = boto3.client('cloudwatch', region_name=aws_region, config=boto_config)
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    inst_id = inst['InstanceId']
                    state = inst['State']['Name']
                    tags_dict = extract_tags(inst.get('Tags', []))
                    
                    if state == 'running':
                        idle_days = get_ec2_idle_days(cloudwatch, inst_id, max_days=30)
                    else:
                        idle_days = 30
                    public_access = 1 if inst.get('PublicIpAddress') else 0
                    
                    is_flagged = 1 if evaluate_policy(tags_dict, public_access, idle_days, policy) else 0
                    
                    records.append({
                        "id": inst_id,
                        "type": "EC2",
                        "region": aws_region,
                        "name": tags_dict.get('Name', inst_id),
                        "tags": json.dumps(tags_dict),
                        "owner_tag": tags_dict.get('owner', ''),
                        "public_access": public_access,
                        "idle_days": idle_days,
                        "est_monthly_cost": 15.0,
                        "created_at": inst.get('LaunchTime', datetime.now(timezone.utc)).isoformat(),
                        "is_flagged": is_flagged,
                        "scan_timestamp": scan_ts
                    })
    except (NoCredentialsError, ClientError):
        raise
    except Exception as e:
        print(f"Error scanning EC2: {e}")
    return records


def scan_s3(policy, scan_ts):
    records = []
    
    boto_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
    
    try:
        s3 = boto3.client('s3', config=boto_config)
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            tags_dict = {}
            try:
                tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags_dict = extract_tags(tag_response.get('TagSet', []))
            except ClientError as e:
                print(f"S3 tagging error for {bucket_name}: {e}")
                
            public_access = 0
            try:
                acl = s3.get_public_access_block(Bucket=bucket_name)
                if not acl['PublicAccessBlockConfiguration']['BlockPublicAcls']:
                    public_access = 1
            except ClientError as e:
                print(f"S3 public access block error for {bucket_name}: {e}")
                
            idle_days = 0 
            is_flagged = 1 if evaluate_policy(tags_dict, public_access, idle_days, policy) else 0
            
            records.append({
                "id": bucket_name,
                "type": "S3",
                "region": "global",
                "name": bucket_name,
                "tags": json.dumps(tags_dict),
                "owner_tag": tags_dict.get('owner', ''),
                "public_access": public_access,
                "idle_days": idle_days,
                "est_monthly_cost": 5.0,
                "created_at": bucket['CreationDate'].isoformat(),
                "is_flagged": is_flagged,
                "scan_timestamp": scan_ts
            })
    except (NoCredentialsError, ClientError):
        raise
    except Exception as e:
        print(f"Error scanning S3: {e}")
    return records


def scan_rds(policy, scan_ts):
    records = []
    
    boto_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
    
    try:
        aws_region = os.getenv("AWS_REGION", "us-east-1")
        rds = boto3.client('rds', region_name=aws_region, config=boto_config)
        cloudwatch = boto3.client('cloudwatch', region_name=aws_region, config=boto_config)
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []):
                db_id = db['DBInstanceIdentifier']
                
                tags_dict = {}
                try:
                    tag_response = rds.list_tags_for_resource(ResourceName=db['DBInstanceArn'])
                    tags_dict = extract_tags(tag_response.get('TagList', []))
                except ClientError as e:
                    print(f"RDS tagging error for {db_id}: {e}")
                    
                public_access = 1 if db.get('PubliclyAccessible', False) else 0
                status = db.get('DBInstanceStatus')
                if status == 'available':
                    idle_days = get_rds_idle_days(cloudwatch, db_id, max_days=14)
                else:
                    idle_days = 14
                
                is_flagged = 1 if evaluate_policy(tags_dict, public_access, idle_days, policy) else 0
                
                records.append({
                    "id": db_id,
                    "type": "RDS",
                    "region": aws_region,
                    "name": db_id,
                    "tags": json.dumps(tags_dict),
                    "owner_tag": tags_dict.get('owner', ''),
                    "public_access": public_access,
                    "idle_days": idle_days,
                    "est_monthly_cost": 50.0,
                    "created_at": db.get('InstanceCreateTime', datetime.now(timezone.utc)).isoformat(),
                    "is_flagged": is_flagged,
                    "scan_timestamp": scan_ts
                })
    except (NoCredentialsError, ClientError):
        raise
    except Exception as e:
        print(f"Error scanning RDS: {e}")
    return records


def save_to_db(records):
    if not records:
        print("No records found to save.")
        return
        
    insert_sql = """
    INSERT OR REPLACE INTO resources (
        id, type, region, name, tags, owner_tag, public_access, 
        idle_days, est_monthly_cost, created_at, is_flagged, scan_timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    
    tuples = [
        (
            r['id'], r['type'], r['region'], r['name'], r['tags'], r['owner_tag'], 
            r['public_access'], r['idle_days'], r['est_monthly_cost'], 
            r['created_at'], r['is_flagged'], r['scan_timestamp']
        ) for r in records
    ]
    
    with get_connection() as conn:
        conn.executemany(insert_sql, tuples)
        flagged_count = sum(1 for r in records if r['is_flagged'] == 1)
        print(f"Saved {len(tuples)} resources to the database ({flagged_count} flagged as rogue).")


def main():
    print("=" * 60)
    start_time = datetime.now()
    print(f"STARTING CLOUD DETECTION SCAN: {start_time}")
    print("=" * 60)
    
    # MITIGATION 4 (Credential Exfiltration):
    # Security audit: detect AWS credentials supplied through environment variables.
    # Production deployments should use IAM roles instead of static credentials.
    if os.environ.get("AWS_ACCESS_KEY_ID"):
        print("[SECURITY AUDIT] WARNING: Local AWS_ACCESS_KEY_ID detected.")
        print("[SECURITY AUDIT] To prevent credential exfiltration, do not use .env files.")
        print("[SECURITY AUDIT] In production, rely exclusively on IAM Instance Profiles.")
        print("-" * 60)
################## Uncomment the line below to strictly enforce this rule and block local execution:
        # sys.exit(1)
    
    policy = load_policy()
    scan_ts = datetime.now(timezone.utc).isoformat()
    all_records = []
    
    try:
        print("Connecting to AWS to scan resources...")
        ec2_records = scan_ec2(policy, scan_ts)
        s3_records = scan_s3(policy, scan_ts)
        rds_records = scan_rds(policy, scan_ts)
        all_records.extend(ec2_records + s3_records + rds_records)
    except (NoCredentialsError, ClientError) as e:
        print(f"CRITICAL ERROR: AWS connection failed. Valid IAM credentials are required.\n{e}")
        sys.exit(1)
    
    save_to_db(all_records)
    
    end_time = datetime.now()
    print(f"Scan completed in {(end_time - start_time).total_seconds():.2f} seconds.")
    print("=" * 60)


if __name__ == "__main__":
    main()
