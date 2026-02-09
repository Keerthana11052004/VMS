#!/usr/bin/env python3
from app import app

# Test the Flask app's static file serving directly
with app.test_client() as client:
    print("Testing Flask app static file serving directly:")
    
    # Test the default static route
    response = client.get('/static/vendor/bootstrap/css/bootstrap.min.css')
    print(f"/static/vendor/bootstrap/css/bootstrap.min.css: {response.status_code}")
    
    # Test our configured static route
    response = client.get('/vms/static/vendor/bootstrap/css/bootstrap.min.css')
    print(f"/vms/static/vendor/bootstrap/css/bootstrap.min.css: {response.status_code}")
    
    # Print the app's configuration
    print("\nApp Configuration:")
    print(f"APPLICATION_ROOT: {app.config.get('APPLICATION_ROOT')}")
    print(f"static_url_path: {app.static_url_path}")
    print(f"static_folder: {app.static_folder}")
    
    # Check what routes are registered
    print("\nRegistered Routes:")
    for rule in app.url_map.iter_rules():
        if 'static' in str(rule):
            print(f"  {rule}")
