import pandas as pd
import numpy as np
import tensorflow as tf
from urllib.parse import urlparse
import os
from datetime import datetime
import whois
import time

# --- UTILS ---
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.icu', '.buzz', '.club', '.work', '.rent', '.online', '.site', '.website', '.io', '.app', '.dev'}

# WHOIS cache for training
whois_cache = {}

def normalize_url(url):
    """Robust normalization for consistent parsing"""
    # Ensure url is a string
    if not isinstance(url, str):
        url = str(url) if url is not None else ""
    
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

def get_domain_age_training(domain):
    """
    Get domain age for training data with caching and rate limiting.
    Returns None if lookup fails.
    """
    global whois_cache
    
    # Check cache first
    if domain in whois_cache:
        return whois_cache[domain]
    
    # Perform WHOIS lookup with rate limiting
    try:
        time.sleep(0.5)  # Rate limiting: 2 requests per second
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            # Handle timezone-aware datetimes by converting to naive
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.now() - creation_date).days
            whois_cache[domain] = age_days
            return age_days
    except Exception as e:
        # Silently fail for training data
        pass
    
    whois_cache[domain] = None
    return None

def extract_features(url, is_safe_data=False):
    # If training on safe data that lacks a scheme, assume https to prevent bias
    if is_safe_data and not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
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
    
    # Feature 8: TLD Reputation (1 if suspicious, 0 otherwise)
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Feature 9: Advanced counts
    at_symbol = url.count('@')
    question_mark = url.count('?')
    
    # Feature 10: Keyword score
    keywords = ['login', 'secure', 'verify', 'update', 'banking', 'account', 'signin', 'admin', 'pay', 'confirm', 'billing']
    keyword_count = sum(1 for kw in keywords if kw in url.lower())
    
    # Feature 11: Path length
    path_len = len(parsed.path)
    
    # Feature 13: Domain Age (with normalization)
    domain_age_days = get_domain_age_training(domain)
    if domain_age_days is None:
        # Use median value as fallback (approximately 5 years)
        domain_age_days = 1825
    # Log-scale normalization for better model performance
    domain_age_normalized = np.log1p(domain_age_days) / 10.0
    
    return [url_len, dots, hyphens, is_https, domain_len, digit_count, subdomains, is_suspicious_tld, at_symbol, question_mark, keyword_count, path_len, domain_age_normalized]

# --- LOAD DATA ---
print("Loading data...")
phish_df = pd.read_csv('dataset/phishing_urls.csv')
phish_df = phish_df.dropna()  # Remove NaN values

# Load both original and expanded safe URLs
safe_df_original = pd.read_csv('dataset/safe_urls.csv')
safe_df_original = safe_df_original.dropna()  # Remove NaN values

try:
    safe_df_expanded = pd.read_csv('dataset/safe_urls_expanded.csv')
    safe_df_expanded = safe_df_expanded.dropna()  # Remove NaN values
    print(f"Loaded {len(safe_df_expanded)} expanded safe URLs")
except FileNotFoundError:
    safe_df_expanded = pd.DataFrame({'URL': []})
    print("Warning: safe_urls_expanded.csv not found, using original only")

# Combine all safe URLs and filter out invalid ones
all_safe_urls = list(safe_df_original['URL']) + list(safe_df_expanded['URL'])
all_safe_urls = [url for url in all_safe_urls if isinstance(url, str) and url.strip()]

# Synthetic safe URLs to balance the model
synthetic_safe = [
    "https://www.nidoos.ae/", "http://www.nidoos.ae", "nidoos.ae",
    "https://khaleejtimes.com", "https://gulfnews.com", "https://www.etisalat.ae",
    "https://www.du.ae", "https://www.amazon.ae", "https://www.noon.com",
    "https://www.government.ae", "https://www.adcb.com", "https://www.emiratesnbd.com",
    "https://www.google.com/search", "https://www.youtube.com/watch",
    "https://www.facebook.com/profile", "https://www.linkedin.com/in/",
    "https://github.com/user/repo", "https://stackoverflow.com/questions/",
]
all_safe_urls.extend(synthetic_safe)

# Filter phishing URLs
phish_urls = [url for url in phish_df['URL'] if isinstance(url, str) and url.strip()]

# Balance the dataset: use equal number of phishing and safe URLs
num_phishing = len(phish_urls)
num_safe = len(all_safe_urls)

print(f"Phishing URLs: {num_phishing}, Safe URLs: {num_safe}")

# Sample to balance if needed
if num_safe > num_phishing:
    # Randomly sample safe URLs to match phishing count
    import random
    random.seed(42)
    all_safe_urls = random.sample(all_safe_urls, num_phishing)
    print(f"Balanced dataset: {num_phishing} phishing, {len(all_safe_urls)} safe")
elif num_phishing > num_safe:
    # Duplicate safe URLs to match phishing count
    multiplier = (num_phishing // num_safe) + 1
    all_safe_urls = all_safe_urls * multiplier
    all_safe_urls = all_safe_urls[:num_phishing]
    print(f"Balanced dataset: {num_phishing} phishing, {len(all_safe_urls)} safe")

# Extract features
print("Extracting features (applying bias correction to safe data)...")
X_phish = [extract_features(u, is_safe_data=False) for u in phish_urls]
X_safe = [extract_features(u, is_safe_data=True) for u in all_safe_urls]

X = np.array(X_phish + X_safe)
y = np.array([1]*len(X_phish) + [0]*len(X_safe))

print(f"Final dataset shape: X={X.shape}, y={y.shape}")
print(f"Phishing samples: {sum(y)}, Safe samples: {len(y) - sum(y)}")

# --- MODEL TRAINING ---
print(f"Training model on {len(X)} samples with 13 features...")
model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation='relu', input_shape=(13,)),
    tf.keras.layers.Dropout(0.2),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dense(16, activation='relu'),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train
model.fit(X, y, epochs=100, batch_size=32, verbose=0)

# Save
model.save('phish_model.h5')
print("Model saved as phish_model.h5")

# Evaluate on a few examples
test_urls = [
    "https://google.com",
    "https://www.nidoos.ae/",
    "http://www.nidoos.ae",
    "nidoos.ae",
    "http://secure-login-verify-account-88234-update.xyz/auth/session-id-99/"
]

for url in test_urls:
    feat = np.array([extract_features(url)])
    pred = model.predict(feat)[0][0]
    print(f"URL: {url:50} | Prediction: {pred:.4f}")
