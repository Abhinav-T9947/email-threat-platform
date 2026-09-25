import joblib

MODEL_PATH = "ml/models/phishing_model.joblib"
VECTORIZER_PATH = "ml/models/tfidf_vectorizer.joblib"

# Load trained model and vectorizer
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("Phishing Email Detector")
print("-" * 30)

email_text = input("\nPaste email text: ")

# Convert email text into TF-IDF features
email_features = vectorizer.transform([email_text])

# Predict
prediction = model.predict(email_features)[0]

# Get probability
probabilities = model.predict_proba(email_features)[0]

legitimate_probability = probabilities[0]
phishing_probability = probabilities[1]

if prediction == 1:
    print("\nPrediction: PHISHING")
else:
    print("\nPrediction: LEGITIMATE")

print(f"Legitimate probability: {legitimate_probability:.2%}")
print(f"Phishing probability: {phishing_probability:.2%}")