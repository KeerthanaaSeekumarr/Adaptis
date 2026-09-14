import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import re
import os

print("Starting training script...")

# 1. Synthesize slightly larger dataset
data = {
    'url': [
        'http://example.com',
        'http://google.com/search?q=hello',
        'http://testweb.com/index.html',
        'http://secure-login.example/verify',
        'http://appleid-secure-vjeh8u2ulu.xyz/verify/login',
        'http://192.168.1.1/admin',
        'http://10.0.0.1/page.php?ref=<script>alert("XSS")</script>',
        'http://example.com/api/v1/query_db?q=\' OR 1=1 --',
        'http://test.com/about.php',
        'http://mybank-update.com/verify-account',
        'http://internal-portal.local/login',
        'http://badguy.com/malware.exe'
    ],
    'label': [0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1] # 0 = benign, 1 = malicious
}

df = pd.DataFrame(data)

def extract_features(url):
    features = {}
    features['length'] = len(url)
    features['num_special'] = sum([1 for c in url if c in ['?', '=', '-', '_', '/', '.']])
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    return features

X = pd.DataFrame([extract_features(url) for url in df['url']])
y = df['label']

model = xgb.XGBClassifier(eval_metric='logloss', use_label_encoder=False)
model.fit(X, y)

model_path = os.path.join(os.path.dirname(__file__), 'url_model.pkl')
joblib.dump(model, model_path)
print(f"Model trained and saved to {model_path}")
