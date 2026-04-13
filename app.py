from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import re
import math
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# LOAD MODEL 
data = pickle.load(open("model2.pkl", "rb"))
model = data["model"]
feature_names = data["features"]

# LOAD TOP DOMAINS
top_domains_df = pd.read_csv("top-1m.csv", header=None)
top_domains = top_domains_df[1].tolist()[:3000]
top_domains = [d.lower().replace("www.", "") for d in top_domains]
top_domains_set = set(top_domains)

# ENTROPY
def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

# FEATURE EXTRACTION
def extract_features(url):
    url = url.strip().lower()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.netloc.replace("www.", "").split(':')[0]
    path = parsed.path

    parts = hostname.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    features = {}

    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)

    features['having_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
    features['count_dots'] = url.count('.')
    features['count_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 1 else 0

    features['has_at'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in hostname else 0
    features['double_slash'] = 1 if url.count('//') > 1 else 0
    features['https_in_domain'] = 1 if 'https' in hostname else 0

    features['https'] = 1 if parsed.scheme == 'https' else 0

    digit_count = sum(c.isdigit() for c in url)
    features['count_digits'] = digit_count
    features['digit_ratio'] = digit_count / len(url) if len(url) > 0 else 0

    features['url_entropy'] = entropy(url)
    features['path_length'] = len(path)
    features['special_char_count'] = sum(c in "!@#$%^&*()_+-=" for c in url)

    keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update']
    features['has_suspicious_words'] = int(any(word in url for word in keywords))

    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    features['suspicious_tld'] = int(any(tld in url for tld in suspicious_tlds))

    features['is_exact_domain_match'] = int(hostname in top_domains_set)
    features['is_base_domain_match'] = int(base_domain in top_domains_set)

    return features

# API 
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data["url"]

    features = extract_features(url)
    df = pd.DataFrame([features], columns=feature_names)

    prediction = model.predict(df)[0]
    proba = model.predict_proba(df)[0]

    confidence = round(max(proba) * 100, 2)

    return jsonify({
        "result": "Legitimate" if prediction == 0 else "Phishing",
        "confidence": confidence,
        "features": features
    })

if __name__ == "__main__":
    app.run(debug=True)