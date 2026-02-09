#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

# Test the login page and check static file URLs
def test_login_page():
    url = "http://localhost:5001/vms/login"
    print(f"Testing login page at: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            # Parse the HTML to check static URLs
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check all link tags (CSS)
            print("\nChecking CSS URLs:")
            links = soup.find_all('link', href=True)
            for link in links:
                href = link['href']
                print(f"  {href}")
                if href.startswith('/static/'):
                    print(f"    ❌ Missing /vms prefix")
                elif href.startswith('/vms/static/'):
                    print(f"    ✅ Correctly prefixed with /vms")
            
            # Check all script tags (JS)
            print("\nChecking JavaScript URLs:")
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                print(f"  {src}")
                if src.startswith('/static/'):
                    print(f"    ❌ Missing /vms prefix")
                elif src.startswith('/vms/static/'):
                    print(f"    ✅ Correctly prefixed with /vms")
            
            # Check all img tags
            print("\nChecking Image URLs:")
            images = soup.find_all('img', src=True)
            for img in images:
                src = img['src']
                print(f"  {src}")
                if src.startswith('/static/'):
                    print(f"    ❌ Missing /vms prefix")
                elif src.startswith('/vms/static/'):
                    print(f"    ✅ Correctly prefixed with /vms")
        
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
        except Exception as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    test_login_page()
    test_static_files()
