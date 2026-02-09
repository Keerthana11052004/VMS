#!/usr/bin/env python3
from app import app

# Test template rendering directly
with app.test_request_context():
    from flask import render_template_string
    
    print("Testing template rendering directly:")
    
    # Create a simple template that uses url_for('static')
    test_template = '''
    <html>
    <head>
        <link href="{{ url_for('static', filename='test.css') }}" rel="stylesheet">
        <script src="{{ url_for('static', filename='test.js') }}"></script>
        <img src="{{ url_for('static', filename='test.png') }}">
    </head>
    <body>
        <h1>Test</h1>
    </body>
    </html>
    '''
    
    # Render the template
    rendered = render_template_string(test_template)
    print("Rendered template:")
    print(rendered)
    
    # Check the generated URLs
    print("\nGenerated URLs:")
    import re
    urls = re.findall(r'(?:src|href)="([^"\']+)"', rendered)
    for url in urls:
        print(f"  {url}")
        if url.startswith('/vms/static/'):
            print(f"    ✅ Correctly prefixed with /vms")
        else:
            print(f"    ❌ Missing /vms prefix")
