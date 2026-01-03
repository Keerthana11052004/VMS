import mysql.connector
import os
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash

def update_password(name, password):
    try:
        # Get database connection details from environment variables
        database_url = os.environ.get('DATABASE_URL', 'mysql+pymysql://root:Violin@12@localhost:3306/vms_pro')
        
        # Parse the database URL to extract components
        if database_url.startswith('mysql'):
            # Remove mysql:// or mysql+pymysql:// prefix
            db_url = database_url.replace('mysql+pymysql://', '').replace('mysql://', '')
            # Extract user:password@host:port/database
            user_pass, host_db = db_url.split('@')
            user, password_db = user_pass.split(':')
            host_port, database = host_db.split('/')
            if ':' in host_port:
                host, port = host_port.split(':')
            else:
                host = host_port
                port = '3306'
        else:
            # Default fallback values
            user = os.environ.get('DB_USER', 'root')
            password_db = os.environ.get('DB_PASSWORD', 'Violin@12')
            host = os.environ.get('DB_HOST', 'localhost')
            port = os.environ.get('DB_PORT', '3306')
            database = 'vms_pro'
        
        cnx = mysql.connector.connect(user=user, password=password_db, host=host, port=int(port), database=database)
        cursor = cnx.cursor()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        query = "UPDATE user SET password_hash = %s WHERE name = %s"
        cursor.execute(query, (hashed_password, name))
        cnx.commit()
        print(f"Password updated for user: {name}")
        cursor.close()
        cnx.close()

    except Exception as e:
        print(f"Error: {e}")

def get_credentials():
    try:
        # Get database connection details from environment variables
        database_url = os.environ.get('DATABASE_URL', 'mysql+pymysql://root:Violin@12@localhost:3306/vms_pro')
        
        # Parse the database URL to extract components
        if database_url.startswith('mysql'):
            # Remove mysql:// or mysql+pymysql:// prefix
            db_url = database_url.replace('mysql+pymysql://', '').replace('mysql://', '')
            # Extract user:password@host:port/database
            user_pass, host_db = db_url.split('@')
            user, password_db = user_pass.split(':')
            host_port, database = host_db.split('/')
            if ':' in host_port:
                host, port = host_port.split(':')
            else:
                host = host_port
                port = '3306'
        else:
            # Default fallback values
            user = os.environ.get('DB_USER', 'root')
            password_db = os.environ.get('DB_PASSWORD', 'Violin@12')
            host = os.environ.get('DB_HOST', 'localhost')
            port = os.environ.get('DB_PORT', '3306')
            database = 'vms_pro'
        
        cnx = mysql.connector.connect(user=user, password=password_db, host=host, port=int(port), database=database)
        cursor = cnx.cursor()
        query = "SELECT name, password_hash, role FROM user"
        cursor.execute(query)

        for (name, password_hash, role) in cursor:
            print(f"{role}: name={name}, password_hash={password_hash}")

        cursor.close()
        cnx.close()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Update password for System Administrator
    update_password("System Administrator", "admin123")

    # Get credentials
    get_credentials()
