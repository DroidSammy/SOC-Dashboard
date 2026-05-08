# File: ml-service/utils/email_features.py
import re
import math


def preprocess_email(text):
    """Clean and normalize email text."""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Decode common HTML entities
    text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&nbsp;', ' ')
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()


def extract_email_features(text):
    """Extract features from email text for phishing detection."""
    original = text
    text = preprocess_email(text)
    features = {}

    # ─── Urgency and pressure language ────────────────────────
    urgency_words = [
        'urgent', 'immediate', 'immediately', 'expire', 'expires', 'expiring',
        'suspended', 'suspend', 'limited time', 'act now', 'action required',
        'verify now', 'confirm now', 'within 24 hours', 'within 48 hours',
        'your account will', 'account has been', 'account may be'
    ]
    found_urgency = [w for w in urgency_words if w in text]
    features['urgency_count'] = len(found_urgency)
    features['has_urgency'] = 1 if found_urgency else 0
    features['urgency_words'] = found_urgency

    # ─── Impersonation keywords ────────────────────────────────
    brands = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'ebay', 'bank', 'chase', 'wells fargo', 'citibank',
        'irs', 'government', 'fedex', 'dhl', 'ups', 'usps', 'linkedin'
    ]
    found_brands = [b for b in brands if b in text]
    features['brand_count'] = len(found_brands)
    features['impersonation_brands'] = found_brands

    # ─── Credential/PII requests ──────────────────────────────
    pii_patterns = [
        'password', 'username', 'user name', 'login', 'credit card',
        'card number', 'cvv', 'ssn', 'social security', 'bank account',
        'routing number', 'date of birth', 'mother\'s maiden', 'pin'
    ]
    found_pii = [p for p in pii_patterns if p in text]
    features['pii_request_count'] = len(found_pii)
    features['asks_for_credentials'] = 1 if found_pii else 0
    features['pii_fields'] = found_pii

    # ─── Link analysis ────────────────────────────────────────
    links = re.findall(r'https?://\S+', original, re.IGNORECASE)
    features['link_count'] = len(links)
    features['has_links'] = 1 if links else 0

    # Suspicious link patterns
    suspicious_link_count = 0
    for link in links:
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
            suspicious_link_count += 1
        if any(w in link.lower() for w in ['verify', 'secure', 'account', 'login', 'signin']):
            suspicious_link_count += 1
    features['suspicious_link_count'] = suspicious_link_count

    # ─── Click-bait phrases ───────────────────────────────────
    click_phrases = [
        'click here', 'click the link', 'click below',
        'verify here', 'confirm here', 'update here',
        'sign in here', 'log in here', 'access here'
    ]
    found_clicks = [p for p in click_phrases if p in text]
    features['click_bait_count'] = len(found_clicks)

    # ─── Phishing patterns ────────────────────────────────────
    phishing_patterns = [
        r'verify your (account|identity|email|information)',
        r'confirm your (account|password|details|information)',
        r'update your (payment|billing|account|information)',
        r'your account (has been|will be|may be) (suspended|locked|closed|disabled)',
        r'unusual (activity|sign-in|login) (detected|noticed)',
        r'we (noticed|detected|found) (suspicious|unusual|unauthorized)',
        r'click (here|below|the link) to (verify|confirm|update|restore)',
    ]
    pattern_matches = []
    for pattern in phishing_patterns:
        if re.search(pattern, text):
            pattern_matches.append(pattern)
    features['pattern_match_count'] = len(pattern_matches)
    features['matched_patterns'] = pattern_matches

    # ─── Grammar/quality signals ──────────────────────────────
    # Lots of exclamation marks = suspicious
    features['exclamation_count'] = original.count('!')
    # All caps words
    caps_words = re.findall(r'\b[A-Z]{3,}\b', original)
    features['caps_word_count'] = len(caps_words)

    # ─── Text length ──────────────────────────────────────────
    features['text_length'] = len(text)
    features['word_count'] = len(text.split())

    return features


def compute_phishing_score(features):
    """Compute a 0-1 phishing probability from features."""
    score = 0.0
    score += min(features.get('urgency_count', 0) * 0.12, 0.36)
    score += min(features.get('brand_count', 0) * 0.10, 0.20)
    score += features.get('asks_for_credentials', 0) * 0.30
    score += min(features.get('pii_request_count', 0) * 0.08, 0.24)
    score += min(features.get('pattern_match_count', 0) * 0.15, 0.45)
    score += min(features.get('click_bait_count', 0) * 0.10, 0.20)
    score += min(features.get('suspicious_link_count', 0) * 0.12, 0.24)
    score += min(features.get('exclamation_count', 0) * 0.02, 0.10)
    return min(score, 1.0)


def highlight_suspicious_phrases(text, features):
    """Return list of suspicious phrases found in the email."""
    suspicious = []
    suspicious.extend(features.get('urgency_words', []))
    suspicious.extend(features.get('pii_fields', []))
    suspicious.extend(['click here', 'click the link', 'click below'][:features.get('click_bait_count', 0)])
    return list(set(suspicious))


def analyze_email(email_content, model=None):
    """Full email phishing analysis."""
    features = extract_email_features(email_content)

    if model is not None:
        try:
            import numpy as np
            # For TF-IDF model, use raw text
            pred = model.predict([preprocess_email(email_content)])[0]
            proba = model.predict_proba([preprocess_email(email_content)])[0]
            confidence = float(max(proba))
            verdict = 'phishing' if pred == 1 else 'legitimate'
            phishing_score = float(proba[1]) if len(proba) > 1 else confidence

            return {
                'verdict': verdict,
                'confidence': round(confidence, 2),
                'phishing_probability': round(phishing_score, 2),
                'flags': features,
                'suspicious_phrases': highlight_suspicious_phrases(email_content, features),
                'model_used': 'Naive Bayes / Logistic Regression',
            }
        except Exception:
            pass

    # Rule-based fallback
    score = compute_phishing_score(features)
    verdict = 'phishing' if score > 0.35 else 'legitimate'
    confidence = score if verdict == 'phishing' else (1.0 - score)

    return {
        'verdict': verdict,
        'confidence': round(confidence, 2),
        'phishing_probability': round(score, 2),
        'flags': {
            'urgency_words': features.get('urgency_words', []),
            'impersonation_brands': features.get('impersonation_brands', []),
            'credential_requests': features.get('pii_fields', []),
            'link_count': features.get('link_count', 0),
            'suspicious_links': features.get('suspicious_link_count', 0),
            'click_bait_phrases': features.get('click_bait_count', 0),
            'phishing_patterns': features.get('pattern_match_count', 0),
        },
        'suspicious_phrases': highlight_suspicious_phrases(email_content, features),
        'model_used': 'Rule-based (run train_models.py for ML model)',
    }