import requests
import json

url = "http://localhost:5000/predict"
data = {"url": "https://paramountassure.com/"}

try:
    response = requests.post(url, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {response.headers.get('Content-Type')}")
    print(f"Response Content: {response.text[:500]}")
except Exception as e:
    print(f"Error: {e}")
