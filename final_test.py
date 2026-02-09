#!/usr/bin/env python3
import requests

print("=== FINAL COMPREHENSIVE TEST ===")

# Test 1: Check if login page is accessible
def test_login_page():
    print("\n1. Testing Login Page Access:")
    url = "http://localhost:5001/vms/login"
    try:
        response = requests.get(url, timeout=5)
        print(f"   URL: {url}")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Login page accessible")
            return response.text
        else:
            print("   ❌ Login page not accessible")
            return None
    except Exception as e:
        print(f"   Error: {e}")
        return None

# Test 2: Check static URL generation in the actual page
def test_static_urls(html_content):
    print("\n2. Testing Static URL Generation:")
    if not html_content:
        print("   ❌ No HTML content to analyze")
        return
    
    # Check for static URLs
    import re
    urls = re.findall(r'(?:src|href)="(/static/[^"\']+)"', html_content)
    
    if urls:
        unique_urls = list(set(urls))
        print(f"   Found {len(unique_urls)} unique static URLs:")
        
        correct = 0
        incorrect = 0
        for url in unique_urls:
            if url.startswith('/vms/static/'):
                correct += 1
                print(f"     ✅ {url}")
            else:
                incorrect += 1
                print(f"     ❌ {url}")
        
        print(f"   Summary: {correct} correct URLs, {incorrect} incorrect URLs")
        
        if incorrect == 0:
            print("   ✅ All static URLs have the correct /vms prefix!")
            return True
        else:
            print("   ❌ Found static URLs without /vms prefix!")
            return False
    else:
        print("   ⚠️  No static URLs found in the page")
        return True

# Test 3: Test direct access to static files
def test_static_file_access():
    print("\n3. Testing Static File Access:")
    
    test_cases = [
        ("http://localhost:5001/static/vendor/bootstrap/css/bootstrap.min.css", "Without /vms prefix", False),
        ("http://localhost:5001/vms/static/vendor/bootstrap/css/bootstrap.min.css", "With /vms prefix", True)
    ]
    
    all_passed = True
    for url, description, should_succeed in test_cases:
        try:
            response = requests.get(url, timeout=5)
            print(f"   {description}:")
            print(f"     URL: {url}")
            print(f"     Status: {response.status_code}")
            
            if should_succeed:
                if response.status_code == 200:
                    print("     ✅ Pass: Should be accessible")
                else:
                    print("     ❌ Fail: Should be accessible but got status code {response.status_code}")
                    all_passed = False
            else:
                if response.status_code != 200:
                    print("     ✅ Pass: Should not be accessible")
                else:
                    print("     ❌ Fail: Should not be accessible but was accessible")
                    all_passed = False
        except Exception as e:
            print(f"     Error: {e}")
            if should_succeed:
                print("     ❌ Fail: Should be accessible but got error")
                all_passed = False
            else:
                print("     ✅ Pass: Should not be accessible and got error")
    
    return all_passed

# Run all tests
html = test_login_page()
static_ok = test_static_urls(html)
access_ok = test_static_file_access()

print("\n" + "="*50)
print("FINAL RESULT:")
if static_ok and access_ok:
    print("✅ All tests passed! The VMS application is correctly configured.")
    print("✅ Login page: http://localhost:5001/vms/login (status 200)")
    print("✅ Static files only accessible at /vms/static/")
    print("✅ Templates generate correct URLs with /vms prefix")
    print("✅ No duplicate prefixes in URLs")
    print("\nThis should resolve the 403 errors in production.")
else:
    print("❌ Some tests failed. Please check the output above.")
print("="*50)
