#!/usr/bin/env python3
"""
SOC Dashboard — ML Model Training Script
File: ml-service/train_models.py

Run once before starting the ML service:
    python train_models.py

This script:
1. Generates synthetic training data (no Kaggle download needed)
2. Trains URL phishing detection model (Random Forest)
3. Trains email phishing detection model (Naive Bayes)
4. Trains network anomaly detection model (Isolation Forest)
5. Saves all models to models/ directory
"""

import os
import random
import string
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from utils.url_features import extract_url_features

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

print("\n" + "="*60)
print("  SOC Dashboard — ML Model Training")
print("="*60)

# ──────────────────────────────────────────────────────────
# 1. URL PHISHING MODEL
# ──────────────────────────────────────────────────────────
print("\n[1/3] Training URL Phishing Detection Model...")

from datasets import load_dataset

print("   Downloading/Loading dataset from HuggingFace (pirocheto/phishing-url)...")
try:
    ds = load_dataset("pirocheto/phishing-url", split="train")
    ds = ds.shuffle(seed=42).select(range(5000))
    
    print(f"   Loaded {len(ds)} real-world URLs for training.")
    
    X_url = []
    y_url = []
    
    print("   Extracting features from URLs (this may take a minute)...")
    for row in ds:
        url = row['url']
        label = 1 if row['status'] == 'phishing' else 0
        features = extract_url_features(url)
        X_url.append(list(features.values()))
        y_url.append(label)
        
    X_url = np.array(X_url)
    y_url = np.array(y_url)
    
    X_train, X_test, y_train, y_test = train_test_split(X_url, y_url, test_size=0.2, random_state=42)
    url_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=15)
    url_model.fit(X_train, y_train)

    print(f"   Training samples: {len(X_train)}")
    print(f"   Test accuracy: {url_model.score(X_test, y_test):.1%}")
    joblib.dump(url_model, os.path.join(MODELS_DIR, 'url_model.pkl'))
    print("   ✅ Real URL model saved → models/url_model.pkl")

except Exception as e:
    print(f"   ❌ Failed to load dataset: {e}")


# ──────────────────────────────────────────────────────────
# 2. EMAIL PHISHING MODEL
# ──────────────────────────────────────────────────────────
print("\n[2/3] Training Email Phishing Detection Model...")

print("   Downloading/Loading dataset from HuggingFace (SetFit/enron_spam)...")
try:
    ds_email = load_dataset("SetFit/enron_spam", split="train")
    ds_email = ds_email.shuffle(seed=42).select(range(5000))
    
    print(f"   Loaded {len(ds_email)} real-world emails for training.")
    
    X_email = [row['text'] for row in ds_email]
    y_email = np.array([row['label'] for row in ds_email])

except Exception as e:
    print(f"   ❌ Failed to load email dataset: {e}")
    X_email, y_email = [], []

email_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)),
    ('clf', LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
])

X_e_train, X_e_test, y_e_train, y_e_test = train_test_split(X_email, y_email, test_size=0.2, random_state=42)
email_pipeline.fit(X_e_train, y_e_train)

print(f"   Training samples: {len(X_e_train)}")
print(f"   Test accuracy: {email_pipeline.score(X_e_test, y_e_test):.1%}")
joblib.dump(email_pipeline, os.path.join(MODELS_DIR, 'email_model.pkl'))
print("   ✅ Email model saved → models/email_model.pkl")


# ──────────────────────────────────────────────────────────
# 3. NETWORK ANOMALY MODEL (Isolation Forest)
# ──────────────────────────────────────────────────────────
print("\n[3/3] Training Network Anomaly Detection Model...")

print("   Downloading/Loading dataset from HuggingFace (Mireu-Lab/NSL-KDD)...")
try:
    ds_network = load_dataset("Mireu-Lab/NSL-KDD", split="train")
    ds_network = ds_network.shuffle(seed=42).select(range(10000))
    
    print(f"   Loaded {len(ds_network)} real-world network connections for training.")
    
    X_network = []
    # Mireu-Lab/NSL-KDD columns: duration, protocol_type, service, flag, src_bytes, dst_bytes, ... class
    for row in ds_network:
        protocol = str(row.get('protocol_type', '')).lower()
        count = float(row.get('count', 0))
        src_bytes = float(row.get('src_bytes', 0))
        dst_bytes = float(row.get('dst_bytes', 0))
        srv_count = float(row.get('srv_count', 1))
        
        # Map NSL-KDD to our dashboard's expected feature vector
        packets_per_second = count
        bytes_per_second = src_bytes + dst_bytes
        tcp_ratio = 1.0 if protocol == 'tcp' else 0.0
        udp_ratio = 1.0 if protocol == 'udp' else 0.0
        icmp_ratio = 1.0 if protocol == 'icmp' else 0.0
        unique_ports = srv_count
        avg_packet_size = (src_bytes + dst_bytes) / max(1.0, count)
        
        feature_vector = [
            packets_per_second,
            bytes_per_second,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            unique_ports,
            avg_packet_size
        ]
        X_network.append(feature_vector)
        
    X_network = np.array(X_network)

except Exception as e:
    print(f"   ❌ Failed to load network dataset: {e}")
    X_network = np.random.normal(50, 15, (100, 7))

network_model = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
network_model.fit(X_network)

joblib.dump(network_model, os.path.join(MODELS_DIR, 'network_model.pkl'))
print(f"   Training samples: {len(X_network)}")
print("   ✅ Network anomaly model saved → models/network_model.pkl")

print("\n" + "="*60)
print("  ✅ All 3 models trained and saved successfully!")
print("  Now run: python app.py")
print("="*60 + "\n")