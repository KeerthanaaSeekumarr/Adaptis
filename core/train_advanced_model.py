import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import re
import os
import math
import random
from urllib.parse import urlparse

print("[ML Pipeline] Starting Advanced Training Script...")

# --- 1. Synthetic Data Generation (10,000 rows) ---
# We will mathematically generate varying structural types of URLs

def generate_benign_url():
    domains = ["google.com", "github.com", "stackoverflow.com", "aws.amazon.com", "microsoft.com", "apple.com", "netflix.com"]
    paths = ["/login", "/about", "/index.html", "/products/view?id=10", "/contact-us", "/docs/api/v1"]
    return f"https://{random.choice(domains)}{random.choice(paths)}"

def generate_malicious_url():
    # Types: DGA (random chars), IP-based, Phishing (lookalikes), SQLi/XSS payloads
    types = ["dga", "ip", "phish", "payload"]
    t = random.choice(types)
    if t == "dga":
        dga = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(15, 30)))
        return f"http://{dga}.xyz/login.php"
    elif t == "ip":
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return f"http://{ip}/admin/config.bak"
    elif t == "phish":
        brands = ["paypal-update-security", "appleid-verify", "microsoft-support-login"]
        return f"https://{random.choice(brands)}.com-{random.randint(100,999)}.info/login"
    else:
        payloads = ["'<script>alert(1)</script>", "1' OR '1'='1", "../../../etc/passwd"]
        return f"http://vulnerable-site.com/search?q={random.choice(payloads)}"

urls = []
labels = []
for _ in range(5000):
    urls.append(generate_benign_url())
    labels.append(0) # Benign
for _ in range(5000):
    urls.append(generate_malicious_url())
    labels.append(1) # Malicious

# Shuffle the dataset
combined = list(zip(urls, labels))
random.shuffle(combined)
urls, labels = zip(*combined)

df = pd.DataFrame({'url': urls, 'label': labels})
print(f"[ML Pipeline] Generated dataset of shape: {df.shape}")

# --- 2. Advanced Feature Extraction ---
def shannon_entropy(s):
    if not s: return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = - sum([p * math.log(p, 2) for p in prob])
    return entropy

def extract_advanced_features(url):
    features = {}
    
    # Basic
    features['length'] = len(url)
    
    # Count specific characters known to be abused
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_special'] = sum([1 for c in url if c in ['?', '=', '_', '@', '%', '&']])
    
    # URL Parsing
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        path = parsed.path
    except:
        netloc = ""
        path = url
        
    features['domain_length'] = len(netloc)
    features['path_depth'] = path.count('/')
    features['entropy'] = shannon_entropy(url)
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc) else 0

    return features

print("[ML Pipeline] Extracting Features...")
X = pd.DataFrame([extract_advanced_features(u) for u in df['url']])
y = df['label']

# --- 3. Model Training ---
print("[ML Pipeline] Training XGBoost Classifier...")
# We use more estimators and a specified max_depth for a more robust model
model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric='logloss')
model.fit(X, y)

# --- 4. Save Artifact ---
model_path = os.path.join(os.path.dirname(__file__), 'url_model.pkl')
joblib.dump(model, model_path)
print(f"[ML Pipeline] SUCCESS: Model generated and saved to {model_path}")
