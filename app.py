from flask import Flask, request, render_template
import joblib
import numpy as np
from feature_extractor import extract_features

app = Flask(__name__)

model = joblib.load("phishing_model.pkl")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"]

    features = extract_features(url)

    features = np.array(features).reshape(1, -1)

    prediction = model.predict(features)[0]

    if prediction == 1:
        result = "Phishing Website"
    else:
        result = "Legitimate Website"

    return render_template("index.html", prediction_text=result)


if __name__ == "__main__":
    app.run(debug=True)