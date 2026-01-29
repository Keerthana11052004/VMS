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
            # Check if tables exist, only create them if they don't exist (preserve existing data)
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            if not tables:  # If no tables exist, initialize fresh database
                print("📊 No existing tables found, initializing database with default users...")
                db.create_all()
                init_database()
            else:
                print("📊 Existing tables found, preserving data...")
                # Just create any missing tables without dropping existing ones
                db.create_all()
                # Only add default users if they don't already exist
                from app import User
                from werkzeug.security import generate_password_hash
                
                # Check and add default users only if they don't exist
                admin_exists = User.query.filter_by(employee_id='VTPL1028').first()
                if not admin_exists:
                    admin_user = User()
                    admin_user.employee_id = 'VTPL1028'
                    admin_user.email = 'keerthana.u@violintec.com'
                    admin_user.password_hash = generate_password_hash('Keerthu@123')
                    admin_user.role = 'admin'
                    admin_user.username = 'keerthana'
                    admin_user.department = 'IT'
                    db.session.add(admin_user)
                    print("👤 Added default admin user")

                hod_exists = User.query.filter_by(employee_id='VTPL1029').first()
                if not hod_exists:
                    hod_user = User()
                    hod_user.employee_id = 'VTPL1029'
                    hod_user.email = 'hod.it@violintec.com'
                    hod_user.password_hash = generate_password_hash('Hod@123')
                    hod_user.role = 'employee'
                    hod_user.username = 'IT HOD'
                    hod_user.department = 'IT'
                    hod_user.is_hod = True
                    db.session.add(hod_user)
                    print("👤 Added default HOD user")

                employee_exists = User.query.filter_by(employee_id='VTPL1030').first()
                if not employee_exists:
                    employee_user = User()
                    employee_user.employee_id = 'VTPL1030'
                    employee_user.email = 'emp123@violintec.com'
                    employee_user.password_hash = generate_password_hash('Emp@123')
                    employee_user.role = 'employee'
                    employee_user.username = 'Test Employee'
                    employee_user.department = 'IT'
                    db.session.add(employee_user)
                    print("👤 Added default employee user")
                
                db.session.commit()

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


