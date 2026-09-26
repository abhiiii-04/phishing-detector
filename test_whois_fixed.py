"""
Updated WHOIS test with timezone fix
"""
import whois
from datetime import datetime

domains = ['nidoos.ae', 'google.com', 'example.com']

print("="*60)
print("WHOIS DOMAIN AGE TEST (WITH TIMEZONE FIX)")
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
            # FIX: Handle timezone-aware datetimes
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            print(f"  ✅ Creation Date: {creation_date}")
            print(f"  ✅ Domain Age: {age_days} days ({age_years:.1f} years)")
        else:
            print(f"  ❌ No creation date found")
            
    except Exception as e:
        print(f"  ❌ WHOIS lookup failed: {e}")

print("\n" + "="*60)
print("If all tests show real ages, the fix is working!")
print("="*60)
