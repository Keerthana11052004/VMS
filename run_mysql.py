#!/usr/bin/env python3
"""
Run VMS Pro with MySQL Database
This script sets up the environment and runs the VMS Pro application with MySQL database.
"""

import os
import sys

def main():
    """Set up environment and run the application"""
    print("🚀 Starting VMS Pro with MySQL Database")
    print("=" * 40)
    
    # Set environment variables for MySQL
    os.environ['DB_TYPE'] = 'mysql'
    os.environ['DATABASE_URL'] = 'mysql+pymysql://root:Violin%4012@localhost/vms_pro'
    
    print("📋 Database Type: MySQL")
    print("🔗 Database URL: mysql+pymysql://root:Violin%4012@localhost/vms_pro")
    print("✅ Environment configured for MySQL")
    print()
    
    # Execute MySQL commands to create database and grant privileges
    import subprocess
    try:
        mysql_command = [
            r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql",
            '-u', 'root',
            '-pViolin@12',
            '-e', """
            CREATE DATABASE IF NOT EXISTS vms_pro;
            CREATE USER IF NOT EXISTS 'vms_user'@'localhost' IDENTIFIED BY 'VMS_P@sswOrd';
            GRANT ALL PRIVILEGES ON vms_pro.* TO 'vms_user'@'localhost';
            FLUSH PRIVILEGES;
            """
        ]
        subprocess.run(mysql_command, check=True)
        print("✅ MySQL database created and privileges granted")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error setting up MySQL: {e}")
        sys.exit(1)

    # Import and run the Flask app
    from app import app

    print("🌐 Starting Flask application...")
    print("📱 Access the application at: http://127.0.0.1:5001")
    print()

    app.run(debug=True, host='0.0.0.0', port=5001)

if __name__ == "__main__":
    main()

