from app import app, db
import mysql.connector

with app.app_context():
    # Get the database connection
    connection = db.engine.raw_connection()
    cursor = connection.cursor()
    
    # Describe the visitor table
    cursor.execute("DESCRIBE visitor")
    columns = cursor.fetchall()
    
    print("Visitor table schema:")
    for column in columns:
        print(f"Column: {column[0]}, Type: {column[1]}, Null: {column[2]}, Key: {column[3]}, Default: {column[4]}, Extra: {column[5]}")
    
    cursor.close()
    connection.close()