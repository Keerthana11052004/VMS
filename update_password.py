#!/usr/bin/env python3
"""
Script to update admin user password in MySQL vms_pro database
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import from the main app
    from app import app, db, User
    from werkzeug.security import generate_password_hash

    def update_user_password():
        with app.app_context():
            try:
                # Find the user by email
                user = User.query.filter_by(email='keerthana.u@violintec.com').first()
                
                if user:
                    # Update the password to 'Keerthu@123'
                    user.password_hash = generate_password_hash('Keerthu@123')
                    db.session.commit()
                    print("Password for keerthana.u@violintec.com updated successfully!")
                    print("Email: keerthana.u@violintec.com")
                    print("New Password: Keerthu@123")
                    print("Role:", user.role)
                else:
                    print("User keerthana.u@violintec.com not found in database!")
                    # Check if any users exist
                    all_users = User.query.all()
                    print(f"Found {len(all_users)} users in database:")
                    for u in all_users:
                        print(f"  - {u.email} (ID: {u.id}, Role: {u.role})")
            except Exception as e:
                print(f"Error updating user password: {e}")
                import traceback
                traceback.print_exc()
                db.session.rollback()

    if __name__ == "__main__":
        update_user_password()
        
except Exception as e:
    print(f"Error importing app: {e}")
    import traceback
    traceback.print_exc()