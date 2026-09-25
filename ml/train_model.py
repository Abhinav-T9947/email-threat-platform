import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score


# -----------------------------
# 1. Load dataset
# -----------------------------

DATASET_PATH = "ml/data/phishing_email.csv"

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Original emails: {len(df)}")


# -----------------------------
# 2. Remove duplicate emails
# -----------------------------

before = len(df)

df = df.drop_duplicates(subset=["text_combined"])

after = len(df)

print(f"Duplicate emails removed: {before - after}")
print(f"Emails remaining: {after}")


# -----------------------------
# 3. Prepare data
# -----------------------------

X = df["text_combined"]
y = df["label"]


# -----------------------------
# 4. Split dataset
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training emails: {len(X_train)}")
print(f"Testing emails: {len(X_test)}")


# -----------------------------
# 5. Convert text to TF-IDF
# -----------------------------

print("\nConverting emails to TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    max_features=100000,
    ngram_range=(1, 2)
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print(f"Training feature matrix: {X_train_tfidf.shape}")


# -----------------------------
# 6. Train model
# -----------------------------

print("\nTraining Logistic Regression model...")

model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

model.fit(X_train_tfidf, y_train)


# -----------------------------
# 7. Evaluate training data
# -----------------------------

train_pred = model.predict(X_train_tfidf)

train_accuracy = accuracy_score(y_train, train_pred)

print(f"\nTraining Accuracy: {train_accuracy:.4f}")


# -----------------------------
# 8. Evaluate test data
# -----------------------------

print("\nEvaluating unseen test emails...")

test_pred = model.predict(X_test_tfidf)

test_accuracy = accuracy_score(y_test, test_pred)

print(f"Test Accuracy: {test_accuracy:.4f}")


# -----------------------------
# 9. Detailed report
# -----------------------------

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        test_pred,
        target_names=["Legitimate", "Phishing"]
    )
)
# -----------------------------
# 10. Save trained model
# -----------------------------

MODEL_PATH = "ml/models/phishing_model.joblib"
VECTORIZER_PATH = "ml/models/tfidf_vectorizer.joblib"

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print("\nModel saved to:", MODEL_PATH)
print("Vectorizer saved to:", VECTORIZER_PATH)