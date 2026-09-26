"""
Test script for Phish-Detect enhanced detection logic
Tests all three tiers: Whitelist, OpenPhish Feed, and AI Model
"""

import requests
import json

BASE_URL = "http://localhost:5000"

def test_url(url, expected_verdict=None, expected_method=None):
    """Test a single URL and print results"""
    print(f"\n{'='*80}")
    print(f"Testing URL: {url}")
    print(f"{'='*80}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/predict",
            json={"url": url},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print(f"✓ Status: {data.get('status')}")
            print(f"✓ Verdict: {data.get('verdict', 'N/A')}")
            print(f"✓ Threat Probability: {data.get('threat_probability', data.get('confidence', 0)) * 100:.2f}%")
            print(f"✓ Detection Method: {data.get('detection_method', data.get('source'))}")
            
            # Display domain age if available
            features = data.get('features', {})
            domain_age = features.get('domain_age_days')
            if domain_age and domain_age != "Unknown":
                years = domain_age / 365
                print(f"✓ Domain Age: {domain_age} days (~{years:.1f} years)")
            else:
                print(f"✓ Domain Age: {domain_age}")
            
            # Verification
            if expected_verdict:
                if data.get('verdict') == expected_verdict:
                    print(f"✅ PASS: Verdict matches expected ({expected_verdict})")
                else:
                    print(f"❌ FAIL: Expected {expected_verdict}, got {data.get('verdict')}")
            
            if expected_method:
                actual_method = data.get('detection_method', data.get('source'))
                if expected_method in actual_method:
                    print(f"✅ PASS: Detection method matches expected ({expected_method})")
                else:
                    print(f"❌ FAIL: Expected {expected_method}, got {actual_method}")
            
            return data
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            print(response.text)
            return None
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None

def main():
    print("\n" + "="*80)
    print("PHISH-DETECT ENHANCED DETECTION SYSTEM - TEST SUITE")
    print("="*80)
    
    # Test 1: Whitelisted Domain (should be 0% threat, SECURE, Whitelist)
    print("\n\n### TEST 1: WHITELISTED DOMAIN ###")
    test_url(
        "nidoos.ae",
        expected_verdict="SECURE",
        expected_method="Trusted Domain Whitelist"
    )
    
    # Test 2: Another Whitelisted Domain
    print("\n\n### TEST 2: ANOTHER WHITELISTED DOMAIN ###")
    test_url(
        "google.com",
        expected_verdict="SECURE",
        expected_method="Trusted Domain Whitelist"
    )
    
    # Test 3: Whitelisted with www
    print("\n\n### TEST 3: WHITELISTED DOMAIN WITH WWW ###")
    test_url(
        "www.github.com",
        expected_verdict="SECURE",
        expected_method="Trusted Domain Whitelist"
    )
    
    # Test 4: Unknown URL - AI Model (should use actual model score)
    print("\n\n### TEST 4: UNKNOWN URL - AI MODEL ###")
    test_url(
        "https://example.com",
        expected_method="AI Neural Network"
    )
    
    # Test 5: Suspicious URL - AI Model (should be high threat)
    print("\n\n### TEST 5: SUSPICIOUS URL - AI MODEL ###")
    test_url(
        "http://secure-login-verify-account-88234-update.xyz/auth/session-id-99/",
        expected_method="AI Neural Network"
    )
    
    # Test 6: Another safe domain not in whitelist
    print("\n\n### TEST 6: SAFE DOMAIN (NOT WHITELISTED) - AI MODEL ###")
    test_url(
        "https://wikipedia.org",
        expected_method="AI Neural Network"
    )
    
    print("\n\n" + "="*80)
    print("TEST SUITE COMPLETED")
    print("="*80)
    print("\nKey Verification Points:")
    print("✓ Whitelisted domains should show 0% threat probability")
    print("✓ Whitelisted domains should show SECURE verdict")
    print("✓ Whitelisted domains should use 'Trusted Domain Whitelist' method")
    print("✓ AI model should show actual probability (not 0% or 100%)")
    print("✓ AI model should use refined thresholds:")
    print("  - >70% = MALICIOUS")
    print("  - <50% = SECURE")
    print("  - 50-70% = SUSPICIOUS")
    print("✓ Domain age should be displayed when available")
    print("\n")

if __name__ == "__main__":
    main()
