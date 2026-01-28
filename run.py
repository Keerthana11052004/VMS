#!/usr/bin/env python3
"""
VMS Pro - Visitor Management System
Startup Script
"""

import os
import sys
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required.")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = {
        'flask': 'flask',
        'flask-sqlalchemy': 'flask_sqlalchemy',
        'flask-login': 'flask_login',
        'flask-wtf': 'flask_wtf',
        'werkzeug': 'werkzeug',
        'qrcode': 'qrcode',
        'pillow': 'PIL',          # Pillow is imported as "PIL"
        'reportlab': 'reportlab'
    }
    
    missing_packages = []
    
    for pkg, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(pkg)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 Install dependencies with:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    
    print("✅ All dependencies are installed")

def create_upload_directory():
    """Create uploads directory if it doesn't exist."""
    upload_dir = Path("uploads")
    if not upload_dir.exists():
        upload_dir.mkdir()
        print("✅ Created uploads directory")

def check_database():
    """Check if database exists and is accessible."""
    db_type = os.environ.get('DB_TYPE', 'sqlite')
    if db_type == 'mysql':
        print("✅ MySQL database is configured, skipping database file check.")
        return
    db_path = Path("vms.db")
    if db_path.exists():
        print("✅ Database file exists")
    else:
        print("ℹ️  Database will be created on first run")

def print_startup_info():
    """Print only the running link (clean output)."""
    # Load environment variables to get URL_PREFIX
    try:
        from dotenv import load_dotenv
        load_dotenv()
        import os
        url_prefix = os.environ.get('URL_PREFIX', '/vms')
    except:
        url_prefix = '/vms'
    
    print("\n🚀 VMS Pro server is running!")
    print(f"🌐 Access it at: http://localhost:5001{url_prefix}")
    print("Press Ctrl+C to stop.\n")

def main():
    """Main startup function."""
    try:
        print("🔍 Checking system requirements...")
        check_python_version()
        check_dependencies()
        create_upload_directory()
        check_database()

        # Import and run the Flask app
        from app import app, db
        from init_db import init_database, drop_all_tables

        with app.app_context():
            # Drop all tables and recreate them to ensure schema consistency
            drop_all_tables()
            db.create_all()
            init_database()

        print_startup_info()

        app.run(
            host='0.0.0.0',
            port=5001,
            debug=True  # This enables the reloader by default when debug is True
        )

    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error starting server: {type(e).__name__}: {e}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("   2. Check if port 5003 is available")
        print("   3. Ensure you have write permissions in the current directory")
        print("   4. Verify your database file is not corrupted (delete vms.db and restart if needed)")
        sys.exit(1)

if __name__ == "__main__":
    main()


