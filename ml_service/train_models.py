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

LEGIT_EMAILS = [
    "Hi team, please find the meeting notes attached. We'll discuss the Q3 results next Tuesday at 2pm. Let me know if you have any questions.",
    "Your order has been shipped! Track your package at our website. Estimated delivery: 3-5 business days.",
    "Thank you for your subscription. Your next billing date is March 15th. You can manage your account in the settings.",
    "Reminder: your dentist appointment is scheduled for tomorrow at 10am. Call us if you need to reschedule.",
    "Hi, I wanted to follow up on our conversation from yesterday. Could you send me the report when you get a chance?",
    "Your password was successfully changed. If you did not make this change, please contact support.",
    "Welcome to the team! Your onboarding session starts Monday at 9am. Please bring a photo ID.",
    "Newsletter: This month's top articles on machine learning and AI. Click to read more.",
    "Payment received. Thank you for your purchase of $29.99. Your receipt is attached.",
    "Project update: The development team has completed sprint 5. Review the progress report here.",
]

PHISHING_EMAILS = [
    "URGENT: Your PayPal account has been suspended! Verify your identity immediately at http://paypal-verify.tk or your account will be permanently closed within 24 hours. Click here to verify now!",
    "Dear Customer, We detected unusual activity on your Amazon account. Please click the link below to verify your credentials: http://amazon-secure.ml/login. Failure to verify will result in account suspension.",
    "Your Apple ID has been locked due to suspicious activity. Confirm your identity by clicking the link below or your account will be permanently deleted. Update your information: http://apple-id.online/confirm",
    "IRS NOTICE: You are eligible for a tax refund of $1,200. To claim your refund immediately, provide your Social Security Number and bank account details at http://irs-refund.ga/claim",
    "Microsoft Security Alert: Your account credentials have been compromised. To prevent unauthorized access, update your password immediately by clicking here. Act now to secure your account!",
    "WINNER NOTICE: You have been selected to receive a $500 Amazon gift card! Click here to claim your prize before it expires in 24 hours. Provide your address and credit card number for verification.",
    "Bank Security Notice: We detected a login from an unusual location. Verify your identity to prevent account suspension. Enter your username, password, and PIN at our secure page immediately.",
    "Netflix Billing Failed: Your payment method has been declined. Update your billing information to continue your subscription. Click here: http://netflix-update.xyz/billing - Act within 48 hours!",
    "Dear User, Your email storage is full (100%). Click the link to verify your account and expand your storage immediately or your account will be deactivated: http://gmail-verify.ml",
    "FEDEX DELIVERY ALERT: Your package could not be delivered. Pay a $2.99 redelivery fee here: http://fedex-redelivery.tk. Package will be returned in 24 hours if fee not paid.",
]

# Generate more synthetic emails
for _ in range(30):
    brand = random.choice(['PayPal', 'Amazon', 'Google', 'Apple', 'Microsoft', 'your bank'])
    urgency = random.choice(['urgent', 'immediate action required', 'act now'])
    PHISHING_EMAILS.append(
        f"URGENT: Your {brand} account requires {urgency}! "
        f"Verify your credentials immediately or your account will be suspended. "
        f"Click here to verify: http://verify-now.{random.choice(['tk','ml','xyz'])}/login "
        f"Provide your username, password, and date of birth."
    )

for _ in range(30):
    topic = random.choice(['project', 'meeting', 'invoice', 'report', 'update'])
    LEGIT_EMAILS.append(
        f"Hi, I wanted to share the latest {topic} with you. "
        f"Please review when you get a chance and let me know your feedback. "
        f"We can discuss further in our next meeting. Thanks!"
    )

all_emails = [(e, 0) for e in LEGIT_EMAILS] + [(e, 1) for e in PHISHING_EMAILS]
random.shuffle(all_emails)
X_email = [e[0] for e in all_emails]
y_email = np.array([e[1] for e in all_emails])

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

np.random.seed(42)
# Normal traffic
n_normal = 1000
normal_data = np.column_stack([
    np.random.normal(50, 15, n_normal),     # packets_per_second
    np.random.normal(70000, 20000, n_normal),# bytes_per_second
    np.random.uniform(0.5, 0.7, n_normal),  # tcp_ratio
    np.random.uniform(0.2, 0.4, n_normal),  # udp_ratio
    np.random.uniform(0.05, 0.15, n_normal),# icmp_ratio
    np.random.randint(1, 5, n_normal),       # unique_ports
    np.random.normal(1400, 200, n_normal),   # avg_packet_size
])
normal_data = np.clip(normal_data, 0, None)

# Anomaly traffic (for contamination)
n_anomaly = 100
anomaly_data = np.column_stack([
    np.random.uniform(500, 2000, n_anomaly),  # packets_per_second (spike)
    np.random.uniform(700000, 3000000, n_anomaly),
    np.random.uniform(0.0, 0.3, n_anomaly),
    np.random.uniform(0.7, 1.0, n_anomaly),
    np.random.uniform(0.0, 0.05, n_anomaly),
    np.random.randint(50, 1024, n_anomaly),
    np.random.uniform(40, 100, n_anomaly),    # tiny packets = port scan
])

X_network = np.vstack([normal_data, anomaly_data])

network_model = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
network_model.fit(X_network)

joblib.dump(network_model, os.path.join(MODELS_DIR, 'network_model.pkl'))
print(f"   Training samples: {len(X_network)}")
print("   ✅ Network anomaly model saved → models/network_model.pkl")

print("\n" + "="*60)
print("  ✅ All 3 models trained and saved successfully!")
print("  Now run: python app.py")
print("="*60 + "\n")