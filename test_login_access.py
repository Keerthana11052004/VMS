#!/usr/bin/env python3
import requests

# Test both possible URLs for the login page
test_urls = [
    "http://localhost:5001/vms/login",
    "http://localhost:5001/login"
]

for url in test_urls:
    print(f"\nTesting: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Content Length: {len(response.content)} bytes")
        # Print first 500 characters of content to see if it's an HTML page
        print(f"First 500 chars: {response.content[:500].decode('utf-8', errors='ignore')[:500]}...")
    except Exception as e:
        print(f"Error: {e}")
