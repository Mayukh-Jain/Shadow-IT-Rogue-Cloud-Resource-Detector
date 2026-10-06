
#Synthetic Data Generator for Shadow IT / Rogue Cloud Resource Detector.


from pathlib import Path
import numpy as np
import pandas as pd


def generate_synthetic_features(
    n_samples: int = 1500, random_seed: int = 42
) -> pd.DataFrame:
    """Generate synthetic cloud resource feature distributions.

    Features:
        - public_access: binary [0, 1] with probabilities [0.70, 0.30] (30% exposed)
        - idle_days: integers from 0 to 120
        - missing_tag_count: integers from 0 to 4 (e.g., Owner, Team, Environment, Project)
        - est_monthly_cost: continuous float rounded to 2 decimals, Exp(mean=15)
        - age_days: integers from 1 to 700 (resource lifetime)
    """
    np.random.seed(random_seed)

    public_access = np.random.choice([0, 1], size=n_samples, p=[0.70, 0.30])
    idle_days = np.random.randint(0, 121, size=n_samples)
    missing_tag_count = np.random.randint(0, 5, size=n_samples)
    est_monthly_cost = np.round(
        np.random.exponential(scale=15.0, size=n_samples), 2
    )
    age_days = np.random.randint(1, 701, size=n_samples)

    return pd.DataFrame(
        {
            "public_access": public_access,
            "idle_days": idle_days,
            "missing_tag_count": missing_tag_count,
            "est_monthly_cost": est_monthly_cost,
            "age_days": age_days,
        }
    )


def categorize_risk_buckets(risk_labels: np.ndarray) -> np.ndarray:
    """Categorize continuous risk scores into risk buckets:
    - 'LOW': score < 34
    - 'MEDIUM': 34 <= score < 67
    - 'HIGH': score >= 67
    """
    conditions = [
        risk_labels < 34.0,
        (risk_labels >= 34.0) & (risk_labels < 67.0),
        risk_labels >= 67.0,
    ]
    choices = ["LOW", "MEDIUM", "HIGH"]
    return np.select(conditions, choices, default="MEDIUM")


def compute_risk_scores(
    features_df: pd.DataFrame,
    noise_mean: float = 0.0,
    noise_std: float = 5.0,
    random_seed: int = 42
) -> pd.DataFrame:
    """Compute rule-informed risk scores with Gaussian noise.

    Base calculation:
        score = 0
        score += public_access * 30
        score += (min(idle_days, 60) / 60) * 20
        score += missing_tag_count * 5
        score += (min(est_monthly_cost, 50) / 50) * 15
        score += (min(age_days, 365) / 365) * 15

    Noise:
        noise ~ Normal(mean=0, std=5)

    Clip:
        risk_label within [0, 100] (rounded to 2 decimals)
    """
    pa = features_df["public_access"].values
    idle = features_df["idle_days"].values
    missing = features_df["missing_tag_count"].values
    cost = features_df["est_monthly_cost"].values
    age = features_df["age_days"].values

    base_score = (
        pa * 30.0
        + (np.minimum(idle, 60) / 60.0) * 20.0
        + missing * 5.0
        + (np.minimum(cost, 50.0) / 50.0) * 15.0
        + (np.minimum(age, 365.0) / 365.0) * 15.0
    )

    rng = np.random.RandomState(random_seed)
    noise = rng.normal(loc=noise_mean, scale=noise_std, size=len(features_df))
    raw_score = base_score + noise
    risk_label = np.round(np.clip(raw_score, 0.0, 100.0), 2)
    risk_bucket = categorize_risk_buckets(risk_label)

    df = features_df.copy()
    df["risk_label"] = risk_label
    df["risk_bucket"] = risk_bucket
    return df


def generate_synthetic_dataset(
    n_samples: int = 1500, random_seed: int = 42
) -> pd.DataFrame:
    """Generate full synthetic dataset with features and risk scores."""
    features_df = generate_synthetic_features(
        n_samples=n_samples, random_seed=random_seed
    )
    dataset_df = compute_risk_scores(features_df, random_seed=random_seed)
    return dataset_df


def validate_dataset(df: pd.DataFrame, output_path: Path) -> None:
    """Validate dataset properties and output summary statistics."""
    print("=" * 60)
    print("DATASET VALIDATION REPORT")
    print("=" * 60)

    # 1. Check file exists and size
    assert output_path.exists(), f"Output file does not exist: {output_path}"
    file_size = output_path.stat().st_size
    assert file_size > 0, f"Output file is empty: {output_path}"
    print(f"File path: {output_path.resolve()}")
    print(f"File size: {file_size:,} bytes")
    print(f"Dataset shape: {df.shape}")

    # 2. Check null counts
    print("\n--- Missing Value Analysis ---")
    null_counts = df.isnull().sum()
    print(null_counts.to_string())
    assert null_counts.sum() == 0, "Found unexpected null values in dataset!"

    # 3. Check risk_label interval [0, 100]
    min_label = df["risk_label"].min()
    max_label = df["risk_label"].max()
    print("\n--- Risk Label Range Check ---")
    print(f"Min risk_label: {min_label:.2f}")
    print(f"Max risk_label: {max_label:.2f}")
    assert (
        min_label >= 0.0 and max_label <= 100.0
    ), f"risk_label out of bounds: [{min_label}, {max_label}]"
    print("Confirmation: All risk_label values are within [0, 100].")

    # 4. Risk bucket distribution percentages
    print("\n--- Risk Bucket Distribution ---")
    bucket_counts = df["risk_bucket"].value_counts()
    bucket_pct = df["risk_bucket"].value_counts(normalize=True) * 100.0
    dist_df = pd.DataFrame({"Count": bucket_counts, "Percentage (%)": bucket_pct.round(2)})
    print(dist_df.to_string())

    # 5. First 5 sample rows
    print("\n--- First 5 Sample Rows ---")
    print(df.head().to_string())
    print("=" * 60)


def main():
    script_dir = Path(__file__).resolve().parent
    output_path = script_dir / "data" / "synthetic_dataset.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    n_samples = 1500
    seed = 42
    print(f"Generating synthetic dataset (N={n_samples:,}, seed={seed})...")
    dataset = generate_synthetic_dataset(n_samples=n_samples, random_seed=seed)

    print(f"Exporting dataset to {output_path} without index...")
    dataset.to_csv(output_path, index=False)

    validate_dataset(dataset, output_path)
    print("\nSynthetic data generation completed successfully!")


if __name__ == "__main__":
    main()
