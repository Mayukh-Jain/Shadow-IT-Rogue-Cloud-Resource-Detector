# Cloud Detection Module

This module is responsible for scanning the AWS infrastructure, checking resources (EC2, S3, RDS) against organizational compliance policies, and writing flagged shadow IT resources into the shared SQLite database.

## Architecture
- **`scanner.py`**: The core execution script. It uses `boto3` to communicate with AWS.
  - **True Idle Detection**: Uses AWS CloudWatch (`get_metric_statistics`) to mathematically determine if EC2 instances and RDS databases are actually idle (by checking CPU Utilization and Database Connections over multi-day periods).
- **`policy.yaml`**: The configuration file that defines which tags are mandatory and what the maximum idle limits are.

## 🛠️ Recent Technical Updates
- **True Idle Detection via CloudWatch**: Replaced naive heuristics (e.g., treating any non-running instance as idle) with actual AWS CloudWatch metrics. The scanner now pulls `CPUUtilization` for EC2 and `DatabaseConnections` for RDS over 14-day/30-day windows to mathematically prove inactivity.
- **Dynamic Region Support**: Replaced hardcoded S3 region lookups and EC2 regions with dynamic `get_bucket_location()` and `os.getenv("AWS_REGION")` capabilities.
- **Resilient Exception Handling**: Added strict `ClientError` try/except blocks to gracefully bypass AccessDenied resources instead of crashing the pipeline.

## Setup & Security Requirements

### 1. IAM Least Privilege Policy (Critical)
To prevent privilege escalation, **never** run this script with `AdministratorAccess`. Create an IAM Role or User with the following minimum required read-only permissions:
```json
{
    "Version": "2026-09-30",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "s3:ListAllMyBuckets",
                "s3:GetBucketTagging",
                "s3:GetBucketPublicAccessBlock",
                "rds:DescribeDBInstances",
                "rds:ListTagsForResource",
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": "*"
        }
    ]
}
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure AWS credentials (optional for testing):
```bash
aws configure
```

3. Run the Detection Engine:
```bash
python scanner.py
```
