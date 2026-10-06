#Model Training and Evaluation Script for Shadow IT Resource Risk Scoring.

from pathlib import Path
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_PATH = SCRIPT_DIR / "data" / "synthetic_dataset.csv"
MODEL_PATH = SCRIPT_DIR / "model.pkl"
REPORT_PATH = SCRIPT_DIR / "evaluation_report.txt"

FEATURES = [
    "public_access",
    "idle_days",
    "missing_tag_count",
    "est_monthly_cost",
    "age_days",
]
TARGET = "risk_label"


def load_or_generate_dataset() -> pd.DataFrame:
    """Load dataset from disk, or generate it if not found."""
    if not DATA_PATH.exists():
        sys.path.insert(0, str(SCRIPT_DIR))
        from generate_synthetic_data import generate_synthetic_dataset

        print(f"Dataset not found at {DATA_PATH}. Generating synthetic dataset (seed=42)...")
        DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
        df_generated = generate_synthetic_dataset(n_samples=1500, random_seed=42)
        df_generated.to_csv(DATA_PATH, index=False)
        print(f"Saved synthetic dataset ({len(df_generated):,} rows) to {DATA_PATH}")

    return pd.read_csv(DATA_PATH)


def train_and_evaluate():
    # 1. Load Dataset
    df = load_or_generate_dataset()
    print(f"Loaded dataset with shape: {df.shape}")

    X = df[FEATURES]
    y = df[TARGET]

    # 2. Train/Test Split (80/20, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # 3. Model Initialization and Training
    model = RandomForestRegressor(
        n_estimators=200,
        max_depth=8,
        random_state=42,
    )
    print("Training RandomForestRegressor(n_estimators=200, max_depth=8, random_state=42)...")
    model.fit(X_train, y_train)

    # 4. Evaluation
    y_pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)

    # 5. Model Serialization
    model_artifact = {"model": model, "features": FEATURES}
    joblib.dump(model_artifact, MODEL_PATH)
    print(f"Saved serialized model artifact to {MODEL_PATH}")

    # 6. Feature Importances
    importances = {
        feat: round(float(imp), 3)
        for feat, imp in zip(FEATURES, model.feature_importances_)
    }

    # 7. Generate Evaluation Report
    report_lines = [
        "=" * 60,
        "SHADOW IT RISK SCORING MODEL - EVALUATION REPORT",
        "=" * 60,
        f"Model: RandomForestRegressor(n_estimators=200, max_depth=8, random_state=42)",
        f"Dataset: {DATA_PATH}",
        f"Total Samples: {len(df):,}",
        f"Training Samples: {len(X_train):,}",
        f"Test Samples: {len(X_test):,}",
        "",
        "--- Evaluation Metrics ---",
        f"Mean Absolute Error (MAE): {mae:.3f}",
        f"R-squared (R2) Score: {r2:.3f}",
        "",
        "--- Feature Importances ---",
    ]
    for feat, imp in sorted(importances.items(), key=lambda x: x[1], reverse=True):
        report_lines.append(f"- {feat}: {imp:.3f}")

    report_lines.append("=" * 60)
    report_content = "\n".join(report_lines)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved evaluation report to {REPORT_PATH}\n")

    # Assertions
    assert MODEL_PATH.exists(), f"Model file not found: {MODEL_PATH}"
    assert REPORT_PATH.exists(), f"Evaluation report not found: {REPORT_PATH}"

    # Print report contents to terminal
    print(report_content)


if __name__ == "__main__":
    train_and_evaluate()
