#!/usr/bin/env python3
"""
Script to add admin user to MySQL vms_pro database
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import from the main app
    from app import app, db, User
    from werkzeug.security import generate_password_hash

    def add_admin_user():
        with app.app_context():
            try:
                # Check if user already exists
                existing_user = User.query.filter_by(email='keerthana.u@violintec.com').first()
                
                if existing_user:
                    print("User with email keerthana.u@violintec.com already exists!")
                    print("Email: keerthana.u@violintec.com")
                    print("Password: Keerthu@123")
                    print("Role: admin")
                else:
                    # Create new admin user
                    new_user = User(
                        employee_id='VTPL1028',
                        email='keerthana.u@violintec.com',
                        password_hash=generate_password_hash('Keerthu@123'),
                        role='admin',
                        username='keerthana',
                        department='IT'
                    )
                    
                    db.session.add(new_user)
                    db.session.commit()
                    print("Admin user 'keerthana.u@violintec.com' added successfully!")
                    print("Email: keerthana.u@violintec.com")
                    print("Password: Keerthu@123")
                    print("Role: admin")
            except Exception as e:
                print(f"Error adding user to database: {e}")
                import traceback
                traceback.print_exc()
                db.session.rollback()

    if __name__ == "__main__":
        add_admin_user()
        
except Exception as e:
    print(f"Error importing app: {e}")
    import traceback
    traceback.print_exc()