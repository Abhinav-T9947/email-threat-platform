import os
import joblib


# --------------------------------
# MODEL PATHS
# --------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "phishing_model.joblib"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "tfidf_vectorizer.joblib"
)


# --------------------------------
# LOAD MODEL
# --------------------------------

model = joblib.load(
    MODEL_PATH
)

vectorizer = joblib.load(
    VECTORIZER_PATH
)


def analyze_email_text(text):
    """
    Analyze email text using the trained
    phishing detection model.
    """

    if not text:
        return {
            "prediction": "unknown",
            "phishing_probability": 0.0
        }

    # Convert text into TF-IDF features
    features = vectorizer.transform(
        [text]
    )

    # Get prediction
    prediction = model.predict(
        features
    )[0]

    # Get probability
    probabilities = model.predict_proba(
        features
    )[0]

    phishing_probability = float(
        probabilities[1]
    )

    if prediction == 1:
        result = "phishing"
    else:
        result = "legitimate"

    return {
        "prediction": result,
        "phishing_probability": phishing_probability
    }


if __name__ == "__main__":

    test_email = """
    Urgent security alert.

    Your account has been compromised.

    Verify your account immediately
    or your account will be suspended.

    Click here to verify your identity.
    """

    result = analyze_email_text(
        test_email
    )

    print("=== ML EMAIL ANALYSIS ===")

    print(
        "Prediction:",
        result["prediction"]
    )

    print(
        "Phishing Probability:",
        f"{result['phishing_probability']:.2%}"
    )