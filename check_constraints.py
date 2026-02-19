from app import app, db

with app.app_context():
    # Get the database connection
    connection = db.engine.raw_connection()
    cursor = connection.cursor()
    
    # Get foreign key constraints for visitor table
    cursor.execute("""
        SELECT CONSTRAINT_NAME, TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME 
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'visitor' 
        AND REFERENCED_TABLE_NAME IS NOT NULL
    """)
    constraints = cursor.fetchall()
    
    print("Foreign key constraints for visitor table:")
    for constraint in constraints:
        print(f"Constraint: {constraint[0]}, Column: {constraint[2]}, References: {constraint[3]}.{constraint[4]}")
    
    cursor.close()
    connection.close()