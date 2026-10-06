"""
Pipeline Scoring Script for Shadow IT / Rogue Cloud Resource Detector.

Bridges the shared SQLite database and the trained ML model:
1. Loads trained model artifact from model.pkl
2. Queries flagged resources (is_flagged = 1) from shared/local.db
3. Extracts and preprocesses features
4. Predicts risk score and risk bucket
5. Records the scoring results into the risk_scores table
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd

# Setup paths
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.db import get_connection

MODEL_PATH = SCRIPT_DIR / "model.pkl"
MODEL_VERSION = "rf-v1"
REQUIRED_TAGS = {"owner", "team", "environment", "project"}


def load_model_artifact(model_path: Path = MODEL_PATH):
    """Load serialized RandomForest model artifact and expected feature list."""
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found at {model_path}. "
            "Please run 'python train_model.py' to generate model.pkl."
        )
    artifact = joblib.load(model_path)
    model = artifact["model"]
    features = artifact["features"]
    print(f"Loaded model artifact from {model_path} (Model type: {type(model).__name__})")
    print(f"Expected features: {features}")
    return model, features


def extract_features_from_row(row: dict) -> dict:
    """
    Extract model features from a resource DB row.
    - public_access: 0 or 1
    - idle_days: int
    - missing_tag_count: computed from tags (mock to 2 if missing)
    - est_monthly_cost: float
    - age_days: computed from created_at (mock to 30 if missing)
    """
    # 1. public_access
    pa = int(row.get("public_access") or 0)

    # 2. idle_days
    idle = int(row.get("idle_days") or 0)

    # 3. est_monthly_cost
    cost = float(row.get("est_monthly_cost") or 0.0)

    # 4. missing_tag_count
    tags_raw = row.get("tags")
    missing_tag_count = 0
    if tags_raw:
        try:
            if isinstance(tags_raw, str):
                parsed_tags = json.loads(tags_raw)
            elif isinstance(tags_raw, dict):
                parsed_tags = tags_raw
            else:
                raise ValueError(f"Tags must be a JSON string or dict, got {type(tags_raw)}")

            # Lowercase keys to match required governance tags
            tag_keys = {str(k).lower() for k in parsed_tags.keys()}
            if row.get("owner_tag"):
                tag_keys.add("owner")

            missing_count = sum(1 for tag in REQUIRED_TAGS if tag not in tag_keys)
            missing_tag_count = min(max(missing_count, 0), 4)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse tags JSON: {e}")
    else:
        missing_tag_count = 4  # If no tags exist, it's missing all 4 required tags

    # 5. age_days
    created_at_raw = row.get("created_at")
    scan_ts_raw = row.get("scan_timestamp")
    
    if not created_at_raw:
        raise ValueError(f"created_at timestamp is missing for resource ID {row.get('id')}")
        
    try:
        created_str = str(created_at_raw).replace("Z", "+00:00")
        created_dt = datetime.fromisoformat(created_str)
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
            
        if scan_ts_raw:
            scan_str = str(scan_ts_raw).replace("Z", "+00:00")
            scan_dt = datetime.fromisoformat(scan_str)
            if scan_dt.tzinfo is None:
                scan_dt = scan_dt.replace(tzinfo=timezone.utc)
        else:
            scan_dt = datetime.now(timezone.utc)

        delta_days = (scan_dt - created_dt).days
        age_days = max(delta_days, 1)
    except ValueError as e:
        raise ValueError(f"Invalid timestamp format in database for resource {row.get('id')}: {e}")

    return {
        "public_access": pa,
        "idle_days": idle,
        "missing_tag_count": missing_tag_count,
        "est_monthly_cost": cost,
        "age_days": age_days,
    }


def categorize_risk_bucket(score: float) -> str:
    """
    Bucket the score strictly as:
    - 'HIGH' (>= 67)
    - 'MEDIUM' (>= 34)
    - 'LOW' (< 34)
    """
    if score >= 67.0:
        return "HIGH"
    elif score >= 34.0:
        return "MEDIUM"
    else:
        return "LOW"


def score_flagged_resources():
    # 1. Load trained model
    model, features = load_model_artifact()

    # 2. Query flagged resources from shared/local.db
    query_sql = "SELECT * FROM resources WHERE is_flagged = 1;"
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query_sql)
        flagged_resources = cursor.fetchall()

    if not flagged_resources:
        print("No flagged resources (is_flagged = 1) found in database to score.")
        return []

    print(f"\nFound {len(flagged_resources)} flagged resource(s) to score.")

    # 3. Process each row, predict, and collect records to insert
    scoring_records = []
    insert_records = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for row in flagged_resources:
        row_dict = dict(row)
        res_id = row_dict["id"]
        feat_dict = extract_features_from_row(row_dict)

        # Build feature DataFrame matching model features order
        input_df = pd.DataFrame([feat_dict])[features]

        # Predict score
        raw_pred = model.predict(input_df)[0]
        score = float(np.clip(raw_pred, 0.0, 100.0))
        score = round(score, 2)
        risk_bucket = categorize_risk_bucket(score)

        scoring_records.append(
            {
                "resource_id": res_id,
                "name": row_dict.get("name"),
                "features": feat_dict,
                "score": score,
                "risk_bucket": risk_bucket,
                "model_version": MODEL_VERSION,
                "scored_at": now_iso,
            }
        )

        insert_records.append(
            (res_id, score, risk_bucket, MODEL_VERSION, now_iso)
        )

    # 4. Insert into risk_scores table
    insert_sql = """
    INSERT OR REPLACE INTO risk_scores (
        resource_id, score, risk_bucket, model_version, scored_at
    ) VALUES (?, ?, ?, ?, ?);
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.executemany(insert_sql, insert_records)
        print(f"Successfully inserted {cursor.rowcount} scored record(s) into risk_scores table.")

    # Print summary
    print("\n" + "=" * 75)
    print("PIPELINE SCORING EXECUTION SUMMARY")
    print("=" * 75)
    for rec in scoring_records:
        f = rec["features"]
        print(
            f"Resource: {rec['resource_id']} ({rec['name']})\n"
            f"  Features: Public={f['public_access']}, Idle={f['idle_days']}d, "
            f"MissingTags={f['missing_tag_count']}, Cost=${f['est_monthly_cost']}, Age={f['age_days']}d\n"
            f"  Score:    {rec['score']} / 100  -->  Risk Bucket: [{rec['risk_bucket']}]\n"
        )
    print("=" * 75)

    return scoring_records


if __name__ == "__main__":
    score_flagged_resources()
