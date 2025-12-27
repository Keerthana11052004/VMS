#!/usr/bin/env python3
"""
Script to check all users in the database
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import from the main app
    from app import app, db, User

    def check_users():
        with app.app_context():
            try:
                # Get all users
                all_users = User.query.all()
                print(f"Found {len(all_users)} users in database:")
                for user in all_users:
                    print(f"  - ID: {user.id}")
                    print(f"    Employee ID: {user.employee_id}")
                    print(f"    Email: {user.email}")
                    print(f"    Role: {user.role}")
                    print(f"    Username: {user.username}")
                    print(f"    Department: {user.department}")
                    print()
            except Exception as e:
                print(f"Error querying users: {e}")
                import traceback
                traceback.print_exc()

    if __name__ == "__main__":
        check_users()
        
except Exception as e:
    print(f"Error importing app: {e}")
    import traceback
    traceback.print_exc()