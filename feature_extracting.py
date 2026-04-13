import pandas as pd
import re
import math
from urllib.parse import urlparse

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
    if not isinstance(url, str) or len(url) == 0:
        return None

    # NORMALIZATION 
    url = url.strip().lower()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.netloc.replace("www.", "").split(':')[0]
    path = parsed.path

    if hostname == "":
        return None

    parts = hostname.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    features = {}

    # BASIC 
    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)

    # STRUCTURE 
    features['having_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
    features['count_dots'] = url.count('.')
    features['count_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 1 else 0

    # SUSPICIOUS 
    features['has_at'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in hostname else 0
    features['double_slash'] = 1 if url.count('//') > 1 else 0
    features['https_in_domain'] = 1 if 'https' in hostname else 0

    # SECURITY 
    features['https'] = 1 if parsed.scheme == 'https' else 0

    # NUMERIC 
    digit_count = sum(c.isdigit() for c in url)
    features['count_digits'] = digit_count
    features['digit_ratio'] = digit_count / len(url) if len(url) > 0 else 0

    # COMPLEXITY 
    features['url_entropy'] = entropy(url)
    features['path_length'] = len(path)
    features['special_char_count'] = sum(c in "!@#$%^&*()_+-=" for c in url)

    # KEYWORDS 
    keywords = ['login', 'verify', 'secure', 'account', 'bank', 'update']
    features['has_suspicious_words'] = int(any(word in url for word in keywords))

    # TLD 
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    features['suspicious_tld'] = int(any(tld in url for tld in suspicious_tlds))

    # DOMAIN TRUST 
    features['is_exact_domain_match'] = int(hostname in top_domains_set)
    features['is_base_domain_match'] = int(base_domain in top_domains_set)

    return features


df = pd.read_csv("urlset.csv", encoding='latin1', on_bad_lines="skip")
df = df.rename(columns={'domain': 'url'})
 
feature_rows = []

for url in df['url']:
    try:
        feats = extract_features(url)
        feature_rows.append(feats if feats else {})
    except:
        feature_rows.append({})

feature_df = pd.DataFrame(feature_rows)

# FINAL DATASET 
final_df = pd.concat([feature_df, df['label']], axis=1)
final_df = final_df.fillna(0)
 
final_df.to_csv("final_dataset_with_features.csv", index=False)

print("Feature extraction complete!")
print(final_df.head())