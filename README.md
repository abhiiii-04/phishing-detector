# Phish-Detect: AI-Powered Phishing Detection System

An advanced phishing detection system that combines AI/ML with real-time threat intelligence and trusted domain whitelisting to provide accurate URL safety analysis.

## Features

### Three-Tier Detection System

1. **Trusted Domain Whitelist** (Highest Priority)
   - Instantly identifies known safe domains
   - Forces 0% threat probability
   - Bypasses AI model for maximum performance
   - Returns SECURE verdict

2. **OpenPhish Live Feed** (Known Threats)
   - Real-time phishing URL database
   - Forces 100% threat probability
   - Returns MALICIOUS verdict

3. **AI Neural Network** (Unknown URLs)
   - 13-feature deep learning model
   - Includes domain age analysis via WHOIS
   - Refined thresholds:
     - **>70% probability**: MALICIOUS
     - **<50% probability**: SECURE
     - **50-70% probability**: SUSPICIOUS
   - Returns actual model probability score

### Domain Age Analysis

- **WHOIS Integration**: Automatically queries domain registration data
- **Caching**: 1-hour cache to prevent rate limiting
- **False Positive Reduction**: Older domains (5+ years) are less likely to be flagged
- **Graceful Fallback**: System works even if WHOIS lookup fails

### Feature Extraction (13 Features)

1. URL Length
2. Dot count
3. Hyphen count
4. HTTPS usage
5. Domain length
6. Digit count in domain
7. Subdomain count
8. TLD reputation (suspicious TLDs flagged)
9. @ symbol count
10. Query parameter count
11. Keyword score (phishing-related keywords)
12. Path length
13. **Domain age** (log-scaled, days since registration)

## Installation

### Prerequisites

- Python 3.8+
- pip package manager

### Setup

1. **Clone or download the project**

```bash
cd c:\Users\Abhijit Lakshmandass\phish_detect
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

Required packages:
- flask
- tensorflow
- numpy
- requests
- python-whois

3. **Train the model** (optional - pre-trained model included)

```bash
python train_model.py
```

Note: Training with WHOIS lookups may take time due to rate limiting (0.5s per domain).

## Usage

### Start the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

### Web Interface

1. Open your browser to `http://localhost:5000`
2. Enter a URL in the input field
3. Click "Execute Scan"
4. View the results:
   - **Threat Probability**: 0-100% risk score
   - **Verdict**: SECURE, SUSPICIOUS, or MALICIOUS
   - **Detection Method**: Shows which tier detected the URL
   - **Domain Age**: Days/years since domain registration
   - **Feature Analysis**: Detailed URL characteristics

### API Endpoint

**POST** `/predict`

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "status": "secure",
  "verdict": "SECURE",
  "threat_probability": 0.0,
  "confidence": 1.0,
  "detection_method": "Trusted Domain Whitelist",
  "source": "Trusted Domain Whitelist",
  "features": {
    "url_length": 21,
    "dots": 1,
    "hyphens": 0,
    "is_https": true,
    "domain_length": 11,
    "digit_count": 0,
    "subdomains": 0,
    "suspicious_tld": false,
    "at_symbols": 0,
    "query_params": 0,
    "keyword_score": 0,
    "path_length": 0,
    "domain_age_days": 9500,
    "tld": ".com"
  }
}
```

## Detection Logic Examples

### Scenario 1: Whitelisted Domain

**Input:** `nidoos.ae`

**Result:**
- Threat Probability: **0%**
- Verdict: **SECURE**
- Detection Method: **Trusted Domain Whitelist**
- Explanation: Domain is in `safe_domains.txt`, AI model is bypassed

### Scenario 2: Known Phishing URL

**Input:** URL from OpenPhish feed

**Result:**
- Threat Probability: **100%**
- Verdict: **MALICIOUS**
- Detection Method: **OpenPhish Live Feed**
- Explanation: URL matches known phishing database

### Scenario 3: Unknown URL (AI Analysis)

**Input:** `http://secure-login-verify-account-88234-update.xyz/auth/session-id-99/`

**Result:**
- Threat Probability: **~90%** (actual model output)
- Verdict: **MALICIOUS** (>70% threshold)
- Detection Method: **AI Neural Network**
- Explanation: Suspicious features detected:
  - Suspicious TLD (.xyz)
  - Multiple phishing keywords (secure, login, verify, account, update)
  - Long URL with suspicious patterns
  - Likely new domain (if WHOIS available)

### Scenario 4: Legitimate but Unusual URL

**Input:** `https://weird-looking-but-old-domain.com`

**Result:**
- Threat Probability: **~40%** (actual model output)
- Verdict: **SECURE** (<50% threshold)
- Detection Method: **AI Neural Network**
- Explanation: Domain age (10+ years) reduces false positive

## Configuration

### Whitelist Management

Edit `safe_domains.txt` to add trusted domains:

```
# UAE Domains
nidoos.ae
etisalat.ae
emirates.com

# Global Trusted Domains
google.com
github.com
```

### Threshold Adjustment

Edit `app.py` to modify AI thresholds:

```python
# Current thresholds
if threat_probability > 0.7:
    verdict = "MALICIOUS"
elif threat_probability < 0.5:
    verdict = "SECURE"
else:
    verdict = "SUSPICIOUS"
```

### WHOIS Cache Timeout

Edit `app.py` to adjust cache duration:

```python
WHOIS_CACHE_TIMEOUT = 3600  # 1 hour (in seconds)
```

## Project Structure

```
phish_detect/
├── app.py                      # Main Flask application
├── train_model.py              # Model training script
├── requirements.txt            # Python dependencies
├── safe_domains.txt            # Trusted domain whitelist
├── phish_model.h5             # Trained ML model
├── templates/
│   └── index.html             # Web interface
└── dataset/
    ├── phishing_urls.csv      # Phishing training data
    ├── safe_urls.csv          # Safe URL training data
    └── safe_urls_expanded.csv # Additional safe URLs
```

## Technical Details

### Model Architecture

- **Input Layer**: 13 features
- **Hidden Layers**: 
  - Dense(64, ReLU) + Dropout(0.2)
  - Dense(32, ReLU)
  - Dense(16, ReLU)
- **Output Layer**: Dense(1, Sigmoid)
- **Optimizer**: Adam
- **Loss**: Binary Crossentropy

### WHOIS Integration

- **Library**: python-whois
- **Rate Limiting**: 0.5s delay between requests during training
- **Caching**: In-memory cache with 1-hour TTL
- **Fallback**: Uses median age (5 years) if lookup fails
- **Normalization**: Log-scale transformation for better model performance

### Performance Considerations

- **Whitelist Check**: O(1) lookup, instant response
- **OpenPhish Feed**: Cached for 1 hour, O(1) lookup
- **AI Prediction**: ~10-50ms inference time
- **WHOIS Lookup**: 1-3s (cached results are instant)

## Troubleshooting

### WHOIS Lookup Failures

If WHOIS lookups fail frequently:
1. Check internet connection
2. Some domains may not have public WHOIS data
3. Rate limiting may be in effect
4. System will use fallback value (5 years) automatically

### Model Accuracy Issues

To retrain the model with better data:
1. Add more examples to `dataset/` folder
2. Run `python train_model.py`
3. Test with various URLs
4. Adjust thresholds in `app.py` if needed

### OpenPhish Feed Not Updating

- Feed is cached for 1 hour
- Check internet connection
- Verify OpenPhish URL is accessible: https://openphish.com/feed.txt

## Future Enhancements

- [ ] SSL certificate analysis
- [ ] DNS record checking
- [ ] Reputation score from multiple threat feeds
- [ ] User feedback loop for model improvement
- [ ] API rate limiting and authentication
- [ ] Database storage for historical analysis

## License

This project is for educational and security research purposes.

## Credits

- **OpenPhish**: Real-time phishing URL feed
- **TensorFlow**: Machine learning framework
- **Flask**: Web framework
- **python-whois**: WHOIS lookup library
