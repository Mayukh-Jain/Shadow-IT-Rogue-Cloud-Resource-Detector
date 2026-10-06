import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

# Paths
base_dir = os.path.dirname(__file__)
data_path = os.path.join(base_dir, "data", "synthetic_dataset.csv")
model_path = os.path.join(base_dir, "model.pkl")

# Create output dir for images
out_dir = os.path.join(base_dir, "evaluation_plots")
os.makedirs(out_dir, exist_ok=True)

# Load data and model
df = pd.read_csv(data_path)
artifact = joblib.load(model_path)
model = artifact["model"]
features = artifact["features"]

X = df[features]
y_true = df["risk_label"]
y_pred = model.predict(X)

# Calculate metrics
mae = mean_absolute_error(y_true, y_pred)
rmse = np.sqrt(mean_squared_error(y_true, y_pred))
r2 = r2_score(y_true, y_pred)

print(f"Metrics - MAE: {mae:.2f}, RMSE: {rmse:.2f}, R2: {r2:.2f}")

# Plot 1: Actual vs Predicted
plt.figure(figsize=(8, 6))
plt.scatter(y_true, y_pred, alpha=0.5, color='blue')
plt.plot([0, 100], [0, 100], color='red', linestyle='--') # Identity line
plt.title('Actual vs Predicted Risk Scores')
plt.xlabel('Actual Risk Score')
plt.ylabel('Predicted Risk Score')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(out_dir, "actual_vs_predicted.png"))
plt.close()

# Plot 2: Residuals Distribution
residuals = y_true - y_pred
plt.figure(figsize=(8, 6))
sns.histplot(residuals, bins=30, kde=True, color='purple')
plt.title('Residuals Distribution (Actual - Predicted)')
plt.xlabel('Error')
plt.ylabel('Frequency')
plt.axvline(x=0, color='red', linestyle='--')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, "residuals.png"))
plt.close()

# Plot 3: Feature Importances
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(8, 6))
sns.barplot(x=importances[indices], y=np.array(features)[indices], palette="viridis")
plt.title('Feature Importances (Random Forest)')
plt.xlabel('Importance Score')
plt.ylabel('Features')
plt.tight_layout()
plt.savefig(os.path.join(out_dir, "feature_importance.png"))
plt.close()

# Plot 4: Risk Bucket Distribution (Predicted vs Actual)
def categorize(scores):
    return np.select([scores < 34, scores < 67], ['LOW', 'MEDIUM'], default='HIGH')

df['actual_bucket'] = categorize(y_true)
df['predicted_bucket'] = categorize(y_pred)

bucket_order = ['LOW', 'MEDIUM', 'HIGH']
actual_counts = df['actual_bucket'].value_counts().reindex(bucket_order).fillna(0)
pred_counts = df['predicted_bucket'].value_counts().reindex(bucket_order).fillna(0)

x = np.arange(len(bucket_order))
width = 0.35

plt.figure(figsize=(8, 6))
plt.bar(x - width/2, actual_counts, width, label='Actual', color='skyblue')
plt.bar(x + width/2, pred_counts, width, label='Predicted', color='salmon')
plt.xlabel('Risk Bucket')
plt.ylabel('Count')
plt.title('Risk Bucket Distribution (Actual vs Predicted)')
plt.xticks(x, bucket_order)
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(out_dir, "bucket_distribution.png"))
plt.close()

print("Plots generated successfully in 'evaluation_plots' directory.")
