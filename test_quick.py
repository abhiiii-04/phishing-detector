"""
Quick test script for Phish-Detect - Tests core functionality
"""

import requests
import json
import sys

def quick_test():
    """Quick test of the three detection tiers"""
    
    print("="*60)
    print("PHISH-DETECT QUICK TEST")
    print("="*60)
    
    test_cases = [
        {
            "name": "Whitelisted Domain (nidoos.ae)",
            "url": "nidoos.ae",
            "expected_prob": 0.0,
            "expected_verdict": "SECURE",
            "expected_method": "Whitelist"
        },
        {
            "name": "Whitelisted Domain (google.com)",
            "url": "google.com",
            "expected_prob": 0.0,
            "expected_verdict": "SECURE",
            "expected_method": "Whitelist"
        },
        {
            "name": "Unknown URL (AI Model)",
            "url": "https://example.com",
            "expected_method": "AI"
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test['name']}")
        print("-" * 60)
        
        try:
            response = requests.post(
                "http://localhost:5000/predict",
                json={"url": test['url']},
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                prob = data.get('threat_probability', data.get('confidence', 0))
                verdict = data.get('verdict', data.get('status', 'N/A').upper())
                method = data.get('detection_method', data.get('source', 'N/A'))
                
                print(f"  Threat Probability: {prob * 100:.2f}%")
                print(f"  Verdict: {verdict}")
                print(f"  Detection Method: {method}")
                
                # Check domain age
                features = data.get('features', {})
                age = features.get('domain_age_days')
                if age and age != "Unknown":
                    print(f"  Domain Age: {age} days ({age/365:.1f} years)")
                
                # Verify expectations
                passed = True
                if 'expected_prob' in test:
                    if abs(prob - test['expected_prob']) < 0.01:
                        print(f"  ✅ Probability: PASS")
                    else:
                        print(f"  ❌ Probability: FAIL (expected {test['expected_prob']}, got {prob})")
                        passed = False
                
                if 'expected_verdict' in test:
                    if verdict == test['expected_verdict']:
                        print(f"  ✅ Verdict: PASS")
                    else:
                        print(f"  ❌ Verdict: FAIL (expected {test['expected_verdict']}, got {verdict})")
                        passed = False
                
                if 'expected_method' in test:
                    if test['expected_method'] in method:
                        print(f"  ✅ Detection Method: PASS")
                    else:
                        print(f"  ❌ Detection Method: FAIL (expected {test['expected_method']}, got {method})")
                        passed = False
                
                if passed:
                    print(f"  ✅ TEST PASSED")
                else:
                    print(f"  ❌ TEST FAILED")
                    
            else:
                print(f"  ❌ HTTP Error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"  ❌ Cannot connect to server. Is Flask running on localhost:5000?")
            sys.exit(1)
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

if __name__ == "__main__":
    quick_test()
