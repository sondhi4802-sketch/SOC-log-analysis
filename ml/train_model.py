import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset
data = pd.read_csv("ml/dataset.csv")

# Features (ignore Label column)
X = data.drop(columns=["Label"])

# Create Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.3,
    random_state=42
)

# Train model
model.fit(X)

# Save model
joblib.dump(model, "ml/anomaly_model.pkl")

print("Model trained successfully!")
print("Saved as ml/anomaly_model.pkl")