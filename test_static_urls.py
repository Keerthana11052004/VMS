#!/usr/bin/env python3
import requests

def test_url(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except Exception as e:
        return f"Error: {e}"

# Test both URL patterns
direct_url = "http://localhost:5001/static/vendor/bootstrap/css/bootstrap.min.css"
prefixed_url = "http://localhost:5001/vms/static/vendor/bootstrap/css/bootstrap.min.css"

print("Testing static file URL access:")
print(f"Direct URL (should fail): {direct_url}")
direct_status = test_url(direct_url)
print(f"Status: {direct_status}")

print(f"\nPrefixed URL (should work): {prefixed_url}")
prefixed_status = test_url(prefixed_url)
print(f"Status: {prefixed_status}")

# Summary
print("\n--- Summary ---")
if direct_status == 404 or "Error" in str(direct_status):
    print("✅ PASS: Direct URL is blocked (as expected)")
else:
    print(f"❌ FAIL: Direct URL should be blocked but returned {direct_status}")

if 200 <= prefixed_status < 300:
    print("✅ PASS: Prefixed URL works correctly")
else:
    print(f"❌ FAIL: Prefixed URL should work but returned {prefixed_status}")
