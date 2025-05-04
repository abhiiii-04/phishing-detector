import requests
import pandas as pd

# Fetch phishing URLs from OpenPhish
url = "https://openphish.com/feed.txt"
response = requests.get(url)

if response.status_code == 200:
    phishing_urls = response.text.split("\n")
    df_phishing = pd.DataFrame(phishing_urls, columns=["URL"])
    df_phishing["Label"] = 1  # 1 = Phishing

    # Save to CSV
    df_phishing.to_csv("dataset/phishing_urls.csv", index=False)
    print("Phishing URLs saved.")

# Fetch safe URLs from our collected file
with open("dataset/safe_urls.txt", "r") as f:
    safe_urls = f.read().splitlines()

df_safe = pd.DataFrame(safe_urls, columns=["URL"])
df_safe["Label"] = 0  # 0 = Safe

# Save to CSV
df_safe.to_csv("dataset/safe_urls.csv", index=False)
print("Safe URLs saved.")

# Combine both datasets into one file
df_combined = pd.concat([df_phishing, df_safe], ignore_index=True)
df_combined.to_csv("dataset/final_dataset.csv", index=False)
print("Final dataset saved as final_dataset.csv")
