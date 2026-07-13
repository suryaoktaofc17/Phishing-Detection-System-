import pandas as pd
import xgboost as xgb
import joblib
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
import pickle

# Load dataset
df = pd.read_csv("phishing.csv")
X = df.iloc[:, 1:-1]
y = df.iloc[:, -1]

# Fix: Ganti label -1 menjadi 0
y = y.replace(-1, 0)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Buat model XGBoost
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    use_label_encoder=False,
    eval_metric='logloss'
)

# Training dan simpan
model.fit(X_train, y_train)

with open("model.pkl", "wb") as file:
    pickle.dump(model, file)
print("Model saved to model.pkl")
print(f"Jumlah fitur input model: {X.shape[1]}")


