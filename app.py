import os
import requests
import time
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import re
from datetime import datetime
import whois

app = Flask(__name__)

# --- CONFIGURATION ---
OPENPHISH_URL = "https://openphish.com/feed.txt"
FEED_CACHE_TIMEOUT = 3600  # 1 hour
feed_cache = set()
last_fetch_time = 0

# WHOIS cache configuration
WHOIS_CACHE_TIMEOUT = 3600  # 1 hour
whois_cache = {}  # {domain: {'age_days': int, 'timestamp': float}}

# Load safe domain whitelist
SAFE_DOMAINS = set()
try:
    with open('safe_domains.txt', 'r') as f:
        SAFE_DOMAINS = {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}
    print(f"Loaded {len(SAFE_DOMAINS)} safe domains to whitelist.")
except FileNotFoundError:
    print("Warning: safe_domains.txt not found. Whitelist disabled.")

def is_whitelisted(url):
    """Check if domain is in the safe whitelist"""
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'https://' + url)
        domain = parsed.netloc.lower()
        # Remove www. for comparison
        domain_no_www = domain[4:] if domain.startswith('www.') else domain
        return domain_no_www in SAFE_DOMAINS or domain in SAFE_DOMAINS
    except:
        return False

# --- ML MODEL SETUP ---
# For demonstration, we'll create a simple model if it doesn't exist
# In a real scenario, you'd load yours: model = tf.keras.models.load_model('model.h5')
MODEL_PATH = 'phish_model.h5'

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.icu', '.buzz', '.club', '.work', '.rent', '.online', '.site', '.website', '.io', '.app', '.dev'}

def create_dummy_model():
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(16, activation='relu', input_shape=(13,)),
        tf.keras.layers.Dense(8, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.save(MODEL_PATH)
    return model

if os.path.exists(MODEL_PATH):
    try:
        model = tf.keras.models.load_model(MODEL_PATH)
        print(f"Loaded model from {MODEL_PATH}. Input shape: {model.input_shape}")
    except Exception as e:
        print(f"Failed to load model: {e}. Creating dummy.")
        model = create_dummy_model()
else:
    model = create_dummy_model()

# --- UTILS ---

def normalize_url(url):
    """Robust normalization for consistent parsing"""
    url = url.lower().strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Create a variant without www for feature extraction
        domain_no_www = domain[4:] if domain.startswith('www.') else domain
        # Path normalization: strip trailing slash
        path = parsed.path.rstrip('/')
        
        normalized = f"{parsed.scheme}://{domain}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized, domain_no_www
    except:
        return url, url

def fetch_realtime_feed():
    global feed_cache, last_fetch_time
    current_time = time.time()
    
    if current_time - last_fetch_time > FEED_CACHE_TIMEOUT:
        try:
            print("Fetching OpenPhish feed...")
            response = requests.get(OPENPHISH_URL, timeout=5)
            if response.status_code == 200:
                feed_cache = set(response.text.splitlines())
                last_fetch_time = current_time
                print(f"Cached {len(feed_cache)} phishing URLs.")
        except Exception as e:
            print(f"Error fetching OpenPhish feed: {e}")
    
    return feed_cache

def get_domain_age(domain):
    """
    Get domain age in days using WHOIS lookup with caching.
    Returns None if lookup fails or data unavailable.
    """
    global whois_cache
    current_time = time.time()
    
    # Check cache first
    if domain in whois_cache:
        cache_entry = whois_cache[domain]
        if current_time - cache_entry['timestamp'] < WHOIS_CACHE_TIMEOUT:
            return cache_entry['age_days']
    
    # Perform WHOIS lookup
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # Handle multiple creation dates (some registrars return a list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            # Handle timezone-aware datetimes by converting to naive
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.now() - creation_date).days
            # Cache the result
            whois_cache[domain] = {
                'age_days': age_days,
                'timestamp': current_time
            }
            print(f"WHOIS: {domain} is {age_days} days old ({age_days/365:.1f} years)")
            return age_days
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
    
    return None

def preprocess_url(url):
    """
    Extracts 13 features from URL:
    1. URL Length
    2. Count of dots
    3. Count of hyphens
    4. Is HTTPS
    5. Domain Length (no www)
    6. Digit count in domain
    7. Subdomain count
    8. TLD Reputation
    9. Count of @
    10. Count of ?
    11. Keyword Score
    12. Path Length
    13. Domain Age (days, log-scaled)
    """
    url, domain = normalize_url(url)
    parsed = urlparse(url)
    
    # Feature 1: URL Length
    url_len = len(url)
    # Feature 2: Dot count
    dots = url.count('.')
    # Feature 3: Hyphen count
    hyphens = url.count('-')
    # Feature 4: Is HTTPS
    is_https = 1 if parsed.scheme == 'https' else 0
    
    # Feature 5: Domain features
    domain_len = len(domain)
    # Feature 6: Digit count in domain
    digit_count = sum(c.isdigit() for c in domain)
    # Feature 7: Subdomain count 
    subdomains = domain.count('.')
    
    # Feature 8: TLD Reputation
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Advanced features
    at_symbol = url.count('@')
    question_mark = url.count('?')
    
    keywords = ['login', 'secure', 'verify', 'update', 'banking', 'account', 'signin', 'admin', 'pay', 'confirm', 'billing']
    keyword_count = sum(1 for kw in keywords if kw in url.lower())
    
    # Feature 12: Path Length
    path_len = len(parsed.path)
    
    # Feature 13: Domain Age (with normalization)
    domain_age_days = get_domain_age(domain)
    if domain_age_days is None:
        # Use median value as fallback (approximately 5 years)
        domain_age_days = 1825
    # Log-scale normalization for better model performance
    domain_age_normalized = np.log1p(domain_age_days) / 10.0  # Scale to reasonable range
    
    # Return as numpy array for the model (13 features)
    features = np.array([[url_len, dots, hyphens, is_https, domain_len, digit_count, subdomains, is_suspicious_tld, at_symbol, question_mark, keyword_count, path_len, domain_age_normalized]], dtype=np.float32)
    
    feature_dict = {
        "url_length": url_len,
        "dots": dots,
        "hyphens": hyphens,
        "is_https": bool(is_https),
        "domain_length": domain_len,
        "digit_count": digit_count,
        "subdomains": subdomains,
        "suspicious_tld": bool(is_suspicious_tld),
        "at_symbols": at_symbol,
        "query_params": question_mark,
        "keyword_score": keyword_count,
        "path_length": path_len,
        "domain_age_days": domain_age_days if domain_age_days else "Unknown",
        "tld": tld if tld else "N/A"
    }
    
    return features, feature_dict

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Normalize for consistent feed check and processing
    # normalize_url returns (normalized_url, domain)
    url, domain = normalize_url(raw_url)
    
    # Extract features for metadata (always needed for display)
    features, feature_metadata = preprocess_url(url)
    
    # TIER 1: Check Whitelist First (Highest Priority - Known Safe Domains)
    # Force 0% threat probability and SECURE verdict
    if is_whitelisted(raw_url):
        return jsonify({
            "status": "secure",
            "verdict": "SECURE",
            "threat_probability": 0.0,
            "confidence": 1.0,
            "detection_method": "Trusted Domain Whitelist",
            "source": "Trusted Domain Whitelist",
            "features": feature_metadata
        })
    
    # TIER 2: Check OpenPhish Feed (Known Malicious URLs)
    # Force 100% threat probability and MALICIOUS verdict
    feed = fetch_realtime_feed()
    if url in feed or raw_url in feed:
        return jsonify({
            "status": "malicious",
            "verdict": "MALICIOUS",
            "threat_probability": 1.0,
            "confidence": 1.0,
            "detection_method": "OpenPhish Live Feed",
            "source": "OpenPhish Live Feed",
            "features": feature_metadata
        })
    
    # TIER 3: AI Model Prediction (Unknown URLs)
    # Use actual model output with refined thresholds
    
    # Robust check for feature shape mismatch
    model_input_dim = model.input_shape[1]
    current_features_dim = features.shape[1]
    
    if current_features_dim != model_input_dim:
        print(f"Feature mismatch: model expects {model_input_dim}, got {current_features_dim}. Adjusting...")
        if current_features_dim > model_input_dim:
            # Truncate features if we have more than the model expects
            features_for_model = features[:, :model_input_dim]
        else:
            # Pad with zeros if we have fewer (unlikely but safe)
            features_for_model = np.pad(features, ((0, 0), (0, model_input_dim - current_features_dim)))
    else:
        features_for_model = features

    prediction = model.predict(features_for_model, verbose=0)[0][0]
    threat_probability = float(prediction)
    
    # Apply refined thresholds
    if threat_probability > 0.7:
        verdict = "MALICIOUS"
        status = "malicious"
    elif threat_probability < 0.5:
        verdict = "SECURE"
        status = "secure"
    else:
        # Intermediate zone (0.5 - 0.7)
        verdict = "SUSPICIOUS"
        status = "suspicious"
    
    return jsonify({
        "status": status,
        "verdict": verdict,
        "threat_probability": round(threat_probability, 4),
        "confidence": round(threat_probability, 4),
        "detection_method": "AI Neural Network",
        "source": "AI Neural Network",
        "features": feature_metadata
    })

if __name__ == '__main__':
    # Ensure templates folder exists
    if not os.path.exists('templates'):
        os.makedirs('templates')
    app.run(debug=True, use_reloader=False, port=5000)
