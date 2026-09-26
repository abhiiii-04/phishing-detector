"""
Quick WHOIS test to check if domain age lookup is working
"""
import whois
from datetime import datetime

domains = ['nidoos.ae', 'google.com', 'example.com']

print("="*60)
print("WHOIS DOMAIN AGE TEST")
print("="*60)

for domain in domains:
    print(f"\n[Testing] {domain}")
    print("-"*60)
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            print(f"  ✅ Creation Date: {creation_date}")
            print(f"  ✅ Domain Age: {age_days} days ({age_years:.1f} years)")
        else:
            print(f"  ❌ No creation date found")
            
    except Exception as e:
        print(f"  ❌ WHOIS lookup failed: {e}")

print("\n" + "="*60)
