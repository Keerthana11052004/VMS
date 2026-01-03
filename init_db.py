#!/usr/bin/env python3
"""
Database Initialization Script for VMS Pro
This script creates the database and tables for the Visitor Management System.
"""

import sys
import os
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus

try:
    from config import Config
except ImportError:
    print("❌ Config module not found. Please make sure config.py exists with DB_TYPE and SQLALCHEMY_DATABASE_URI.")
    sys.exit(1)


def create_database():
    """Create the database if it doesn't exist"""
    db_type = Config.DB_TYPE.lower()

    if db_type == 'mysql':
        try:
            # Extract MySQL connection details from DATABASE_URL
            database_url = Config.SQLALCHEMY_DATABASE_URI
            import re
            # Pattern to extract user, password, host, port from mysql url
            pattern = r"mysql\\+pymysql://([^:]+):([^@]+)@([^:/]+):?(\\d+)?/"
            match = re.match(pattern, database_url)
            if match:
                user, password, host, port = match.groups()
                port = port or '3306'  # default MySQL port
                password = quote_plus(password)
                engine = create_engine(f"mysql+pymysql://{user}:{password}@{host}:{port}/")
            else:
                # Fallback: extract from environment variables
                import os
                user = os.environ.get('DB_USER', 'root')
                password = os.environ.get('DB_PASSWORD', 'Violin@12')
                host = os.environ.get('DB_HOST', 'localhost')
                port = os.environ.get('DB_PORT', '3306')
                password = quote_plus(password)
                engine = create_engine(f"mysql+pymysql://{user}:{password}@{host}:{port}/")

            with engine.connect() as conn:
                conn.execute(text("CREATE DATABASE IF NOT EXISTS vms_pro"))
                print("✅ MySQL database 'vms_pro' created successfully!")

        except Exception as e:
            print(f"❌ Error creating MySQL database: {e}")
            print("Please make sure MySQL is running and the credentials are correct.")
            return False

    elif db_type == 'postgresql':
        try:
            # Extract PostgreSQL connection details from DATABASE_URL
            database_url = Config.SQLALCHEMY_DATABASE_URI
            import re
            # Pattern to extract user, password, host, port from postgresql url
            pattern = r"postgresql://([^:]+):([^@]+)@([^:/]+):?(\d+)?/"
            match = re.match(pattern, database_url)
            if match:
                user, password, host, port = match.groups()
                port = port or '5432'  # default PostgreSQL port
                password = quote_plus(password)
                engine = create_engine(f"postgresql://{user}:{password}@{host}:{port}/postgres")
            else:
                # Fallback: extract from environment variables
                import os
                user = os.environ.get('DB_USER', 'postgres')
                password = os.environ.get('DB_PASSWORD', 'Violin@12')
                host = os.environ.get('DB_HOST', 'localhost')
                port = os.environ.get('DB_PORT', '5432')
                password = quote_plus(password)
                engine = create_engine(f"postgresql://{user}:{password}@{host}:{port}/postgres")

            with engine.connect() as conn:
                result = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname='vms_pro'")
                ).fetchone()
                if not result:
                    conn.execute(text("COMMIT"))  # finish transaction
                    conn.execute(text("CREATE DATABASE vms_pro"))
                    print("✅ PostgreSQL database 'vms_pro' created successfully!")
                else:
                    print("ℹ️  PostgreSQL database 'vms_pro' already exists")

        except Exception as e:
            print(f"❌ Error creating PostgreSQL database: {e}")
            print("Please make sure PostgreSQL is running and the credentials are correct.")
            return False

    elif db_type == 'sqlite':
        print("ℹ️  Using SQLite — database will be created automatically if it does not exist.")

    else:
        print(f"❌ Unsupported database type '{db_type}' in config.py")
        return False

    return True


def drop_all_tables():
    """Drops all existing database tables."""
    try:
        from app import app, db
        with app.app_context():
            db.drop_all()
            print("✅ All database tables dropped successfully!")
        return True
    except Exception as e:
        print(f"❌ Error dropping database tables: {type(e).__name__}: {e}")
        return False

def init_database():
    """Initialize the database with tables and default data"""
    try:
        from app import app, db, User # Import User from app directly
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Drop all existing tables to ensure the new schema is applied
            db.drop_all()
            print("✅ All database tables dropped successfully!")
            
            # Create all tables with the new schema
            db.create_all()
            print("✅ Database tables created successfully with updated schema!")

            # Add only the specific admin user if not exists
            from werkzeug.security import generate_password_hash
            from app import User  # Import User model here
            
            existing_user = User.query.filter_by(email='keerthana.u@violintec.com').first()
            if not existing_user:
                admin_user = User(
                    employee_id='VTPL1028',
                    email='keerthana.u@violintec.com',
                    password_hash=generate_password_hash('Keerthu@123'),
                    role='admin',
                    username='keerthana',
                    department='IT',
                )
                db.session.add(admin_user)
            
            # Add sample HOD user for testing
            existing_hod = User.query.filter_by(email='hod.it@violintec.com').first()
            if not existing_hod:
                hod_user = User(
                    employee_id='VTPL1029',
                    email='hod.it@violintec.com',
                    password_hash=generate_password_hash('Hod@123'),
                    role='employee',
                    username='IT HOD',
                    department='IT',
                    is_hod=True,
                )
                db.session.add(hod_user)
            
            # Add sample employee for testing
            existing_employee = User.query.filter_by(email='emp123@violintec.com').first()
            if not existing_employee:
                employee_user = User(
                    employee_id='VTPL1030',
                    email='emp123@violintec.com',
                    password_hash=generate_password_hash('Emp@123'),
                    role='employee',
                    username='Test Employee',
                    department='IT',
                )
                db.session.add(employee_user)
            
            db.session.commit()
            print("✅ Database initialized with admin, HOD, and test employee users!")

    except Exception as e:
        print(f"❌ Error initializing database: {type(e).__name__}: {e}")
        return False

    return True


def main():
    """Main function to run database initialization"""
    print("🚀 VMS Pro Database Initialization")
    print("=" * 40)

    print(f"📋 Database Type: {Config.DB_TYPE}")
    print(f"🔗 Database URL: {Config.SQLALCHEMY_DATABASE_URI}")
    print()

    if not create_database():
        sys.exit(1)

    # Removed drop_all_tables() calls to allow init_database() to create tables on first run
    if not init_database():
        sys.exit(1)

    print("\n✅ Database setup completed successfully!")
    print("You can now run the application with: python run.py")


if __name__ == "__main__":
    main()
