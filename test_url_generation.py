#!/usr/bin/env python3
from app import app

# Test URL generation with a test request context
with app.test_request_context():
    from flask import url_for
    
    print("Testing URL Generation:")
    print(f"APPLICATION_ROOT: {app.config.get('APPLICATION_ROOT')}")
    print(f"static_url_path: {app.static_url_path}")
    print(f"URL_PREFIX: {app.config.get('URL_PREFIX')}")
    
    # Test static URL generation
    static_url = url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css')
    print(f"Static URL: {static_url}")
    
    # Test route URL generation
    login_url = url_for('login')
    print(f"Login URL: {login_url}")
