# ============================================================
# SOC Dashboard — ML Service (Python Flask)
# File: ml-service/app.py
# Run: python app.py
# ============================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import json
import requests
import hashlib
import ssl
import socket
from datetime import datetime

from utils.url_features import extract_url_features, predict_url
from utils.email_features import analyze_email
from utils.password_checker import analyze_password
from utils.vuln_scanner import scan_target
from utils.live_sniffer import start_sniffer, get_live_features

app = Flask(__name__)
CORS(app)

# Load trained models (if they exist)
URL_MODEL = None
EMAIL_MODEL = None
NETWORK_MODEL = None

def load_models():
    global URL_MODEL, EMAIL_MODEL, NETWORK_MODEL
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    
    try:
        if os.path.exists(os.path.join(models_dir, 'url_model.pkl')):
            URL_MODEL = joblib.load(os.path.join(models_dir, 'url_model.pkl'))
            print('✅ URL model loaded')
        else:
            print('⚠️  URL model not found — run train_models.py first')
    except Exception as e:
        print(f'❌ URL model load error: {e}')

    try:
        if os.path.exists(os.path.join(models_dir, 'email_model.pkl')):
            EMAIL_MODEL = joblib.load(os.path.join(models_dir, 'email_model.pkl'))
            print('✅ Email model loaded')
        else:
            print('⚠️  Email model not found — run train_models.py first')
    except Exception as e:
        print(f'❌ Email model load error: {e}')

    try:
        if os.path.exists(os.path.join(models_dir, 'network_model.pkl')):
            NETWORK_MODEL = joblib.load(os.path.join(models_dir, 'network_model.pkl'))
            print('✅ Network anomaly model loaded')
    except Exception as e:
        print(f'❌ Network model load error: {e}')


# ──────────────────────────────────────────────────────────
# Health Check
# ──────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'models': {
            'url': URL_MODEL is not None,
            'email': EMAIL_MODEL is not None,
            'network': NETWORK_MODEL is not None,
        },
        'timestamp': datetime.now().isoformat()
    })


# ──────────────────────────────────────────────────────────
# URL Phishing Prediction
# ──────────────────────────────────────────────────────────
@app.route('/predict/url', methods=['POST'])
def predict_url_route():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        result = predict_url(url, URL_MODEL)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'verdict': 'unknown', 'confidence': 0}), 500


# ──────────────────────────────────────────────────────────
# Email Phishing Detection
# ──────────────────────────────────────────────────────────
@app.route('/predict/email', methods=['POST'])
def predict_email_route():
    data = request.get_json()
    email_content = data.get('email_content', '').strip()

    if not email_content:
        return jsonify({'error': 'Email content is required'}), 400

    try:
        result = analyze_email(email_content, EMAIL_MODEL)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────────────────
# Password Security Analysis
# ──────────────────────────────────────────────────────────
@app.route('/analyze/password', methods=['POST'])
def analyze_password_route():
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    try:
        result = analyze_password(password)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────────────────
# Vulnerability Scanner
# ──────────────────────────────────────────────────────────
@app.route('/scan/vulnerability', methods=['POST'])
def scan_vulnerability_route():
    data = request.get_json()
    target_url = data.get('target_url', '').strip()

    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400

    try:
        result = scan_target(target_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────────────────
# Network Anomaly Prediction
# ──────────────────────────────────────────────────────────
@app.route('/predict/network', methods=['POST'])
def predict_network_route():
    data = request.get_json()
    features = data.get('features', {})

    try:
        import numpy as np
        if features.get('mode') == 'live':
            features = get_live_features()
            
        feature_vector = [
            features.get('packets_per_second', 0),
            features.get('bytes_per_second', 0),
            features.get('tcp_ratio', 0.6),
            features.get('udp_ratio', 0.3),
            features.get('icmp_ratio', 0.1),
            features.get('unique_ports', 1),
            features.get('avg_packet_size', 1400),
        ]

        if NETWORK_MODEL:
            pred = NETWORK_MODEL.predict([feature_vector])[0]
            score = NETWORK_MODEL.decision_function([feature_vector])[0]
            is_anomaly = pred == -1
        else:
            # Simple rule-based fallback
            pps = features.get('packets_per_second', 0)
            is_anomaly = pps > 300
            score = -0.8 if is_anomaly else 0.5

        return jsonify({
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(score),
            'severity': 'high' if is_anomaly and features.get('packets_per_second', 0) > 500 else ('medium' if is_anomaly else 'none'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────────────────
# HaveIBeenPwned Password Breach Check
# ──────────────────────────────────────────────────────────
@app.route('/check/breach', methods=['POST'])
def check_breach_route():
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password required'}), 400

    try:
        # k-anonymity: only send first 5 chars of SHA1 hash
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        hibp_key = os.getenv('HIBP_API_KEY', '')
        headers = {'User-Agent': 'SOC-Dashboard-v1'}
        if hibp_key and hibp_key != 'your_haveibeenpwned_key_here':
            headers['hibp-api-key'] = hibp_key

        resp = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers=headers,
            timeout=8
        )

        if resp.status_code == 200:
            hashes = resp.text.splitlines()
            count = 0
            for line in hashes:
                h, c = line.split(':')
                if h.upper() == suffix:
                    count = int(c)
                    break
            return jsonify({'breached': count > 0, 'count': count})
        else:
            return jsonify({'breached': False, 'count': 0, 'error': 'HIBP API error'})
    except Exception as e:
        return jsonify({'breached': False, 'count': 0, 'error': str(e)})


if __name__ == '__main__':
    print('\n🔬 SOC Dashboard ML Service starting...')
    load_models()
    start_sniffer()
    print('🚀 ML Service running on http://localhost:5001\n')
    app.run(host='0.0.0.0', port=5001, debug=False)