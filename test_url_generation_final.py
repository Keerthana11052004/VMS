#!/usr/bin/env python3
from app import app

# Test URL generation with different approaches
with app.test_request_context():
    from flask import url_for
    
    print("Testing URL Generation:")
    print(f"static_url_path: {app.static_url_path}")
    print(f"URL_PREFIX: {app.config.get('URL_PREFIX')}")
    
    # Test 1: Default url_for('static')
    static_url = url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css')
    print(f"\n1. url_for('static'): {static_url}")
    
    # Test 2: url_for('static') with _external=True
    static_url_external = url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css', _external=True)
    print(f"2. url_for('static', _external=True): {static_url_external}")
    
    # Test 3: url_for with different parameters
    static_url_root = url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css', _external=True, _scheme='http', _server='localhost:5001')
    print(f"3. url_for with explicit _server: {static_url_root}")
    
    # Test 4: Login URL for comparison
    login_url = url_for('login')
    print(f"4. url_for('login'): {login_url}")
    
    # Test 5: Check if APPLICATION_ROOT affects URL generation
    print(f"\n5. APPLICATION_ROOT: {app.config.get('APPLICATION_ROOT')}")
    
    # Test 6: Let's try setting SCRIPT_NAME explicitly
    with app.test_request_context(script_name='/vms'):
        static_url_script = url_for('static', filename='vendor/bootstrap/css/bootstrap.min.css')
        print(f"6. With script_name='/vms': {static_url_script}")
