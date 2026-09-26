"""
Simple API test to check WHOIS domain ages
"""
import requests
import json

print("="*60)
print("TESTING WHOIS DOMAIN AGES VIA API")
print("="*60)

test_urls = [
    ("nidoos.ae", "Should show actual age of nidoos.ae domain"),
    ("google.com", "Should show ~26+ years (registered 1997)"),
    ("example.com", "Should show ~30+ years (very old domain)")
]

for url, description in test_urls:
    print(f"\n[Testing] {url}")
    print(f"Expected: {description}")
    print("-"*60)
    
    try:
        response = requests.post(
            "http://localhost:5000/predict",
            json={"url": url},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            features = data.get('features', {})
            age_days = features.get('domain_age_days')
            
            if age_days and age_days != "Unknown" and age_days != 1825:
                age_years = age_days / 365
                print(f"  SUCCESS: Domain Age = {age_days} days ({age_years:.1f} years)")
            elif age_days == 1825:
                print(f"  FALLBACK: Using default value (1825 days / 5 years)")
                print(f"  This means WHOIS lookup failed or timed out")
            else:
                print(f"  UNKNOWN: Domain age = {age_days}")
        else:
            print(f"  ERROR: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"  ERROR: {e}")

print("\n" + "="*60)
print("If you see 'SUCCESS' with different ages, WHOIS is working!")
print("If you see 'FALLBACK' for all, WHOIS lookups are failing.")
print("="*60)
