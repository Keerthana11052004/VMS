#!/usr/bin/env python3
import requests

# Test the login page and check static file URLs
def test_login_page():
    url = "http://localhost:5001/vms/login"
    print(f"Testing login page at: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            # Check the HTML content directly for static URLs
            html = response.text
            
            print("\nChecking static file references:")
            
            # Count occurrences of static URLs with and without /vms prefix
            static_without_prefix = html.count('/static/')
            static_with_prefix = html.count('/vms/static/')
            
            print(f"  URLs with /static/: {static_without_prefix}")
            print(f"  URLs with /vms/static/: {static_with_prefix}")
            
            if static_without_prefix > 0:
                print("\n❌ ERROR: Found static URLs without /vms prefix!")
                # Show some examples
                lines = html.split('\n')
                for i, line in enumerate(lines):
                    if '/static/' in line and '/vms/static/' not in line:
                        print(f"   Line {i+1}: {line.strip()[:100]}...")
            else:
                print("\n✅ All static URLs have the correct /vms prefix!")
        
    except Exception as e:
        print(f"Error: {e}")

# Test direct access to static files with and without prefix
def test_static_files():
    print("\n" + "="*50)
    print("Testing static file access:")
    
    test_urls = [
        ("http://localhost:5001/static/vendor/bootstrap/css/bootstrap.min.css", "Without /vms prefix"),
        ("http://localhost:5001/vms/static/vendor/bootstrap/css/bootstrap.min.css", "With /vms prefix")
    ]
    
    for url, description in test_urls:
        print(f"\n{description}: {url}")
        try:
            response = requests.get(url, timeout=5)
            print(f"  Status Code: {response.status_code}")
            if response.status_code == 200:
                print(f"    ✅ Accessible")
            else:
                print(f"    ❌ Not accessible")
        except Exception as e:
            print(f"    Error: {e}")

if __name__ == "__main__":
    test_login_page()
    test_static_files()
