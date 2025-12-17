#!/usr/bin/env python3
"""
Database Initialization Script for VMS Pro
This script creates the database and tables for the Visitor Management System.
"""

import sys
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
            password = quote_plus("Violin@12")
            engine = create_engine(f"mysql+pymysql://root:{password}@localhost/")

            with engine.connect() as conn:
                conn.execute(text("CREATE DATABASE IF NOT EXISTS vms_pro"))
                print("✅ MySQL database 'vms_pro' created successfully!")

        except Exception as e:
            print(f"❌ Error creating MySQL database: {e}")
            print("Please make sure MySQL is running and the credentials are correct.")
            return False

    elif db_type == 'postgresql':
        try:
            password = quote_plus("Violin@12")
            engine = create_engine(f"postgresql://root:{password}@localhost/postgres")

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
            db.create_all()
            print("✅ Database tables created successfully!")

            defaults = [
                {"username": "admin", "email": "admin@vms.com", "password": "admin123", "role": "admin", "name": "System Administrator", "department": "IT", "employee_id": "admin123"},
                {"username": "employee", "email": "employee@vms.com", "password": "employee123", "role": "employee", "name": "John Doe", "department": "Sales", "employee_id": "emp123"},
                {"username": "security", "email": "security@vms.com", "password": "security123", "role": "security", "name": "Security Guard", "department": "Security", "employee_id": "sec123"},
            ]

            for u in defaults:
                existing_user = User.query.filter_by(email=u["email"]).first()
                if not existing_user:
                    user = User(
                        employee_id=u["employee_id"],
                        email=u["email"],
                        password_hash=generate_password_hash(u["password"]),
                        role=u["role"],
                        username=u["username"],
                        department=u["department"],
                    )
                    db.session.add(user)

            db.session.commit()
            print("✅ Default users ensured in database!")

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
