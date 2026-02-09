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
            
            # Find all static URLs using a better approach
            lines = html.split('\n')
            all_static_urls = []
            
            for i, line in enumerate(lines):
                # Check for src="/static/..." or href="/static/..." patterns
                if '/static/' in line:
                    # Extract the URL
                    import re
                    urls = re.findall(r'(?:src|href)="(/static/[^"\']+)"', line)
                    all_static_urls.extend(urls)
            
            # Print unique URLs
            unique_urls = list(set(all_static_urls))
            print(f"  Found {len(unique_urls)} unique static URLs:")
            
            # Count correct vs incorrect URLs
            correct_urls = []
            incorrect_urls = []
            
            for url in unique_urls:
                if url.startswith('/vms/static/'):
                    correct_urls.append(url)
                    print(f"    ✅ {url}")
                else:
                    incorrect_urls.append(url)
                    print(f"    ❌ {url}")
            
            print(f"\n  Summary: {len(correct_urls)} correct URLs, {len(incorrect_urls)} incorrect URLs")
            
            if incorrect_urls:
                print("\n❌ ERROR: Found static URLs without /vms prefix!")
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
