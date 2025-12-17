import mysql.connector
from werkzeug.security import generate_password_hash

def update_password(name, password):
    try:
        cnx = mysql.connector.connect(user='root', password='Violin@12', host='localhost', database='vms_pro')
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
        cnx = mysql.connector.connect(user='root', password='Violin@12', host='localhost', database='vms_pro')
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
