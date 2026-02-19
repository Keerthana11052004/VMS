from app import app, db, User

with app.app_context():
    user = User.query.get(0)
    print('User with ID 0:', user)
    
    # Check all users
    print('All users:')
    users = User.query.all()
    for u in users:
        print(f'ID: {u.id}, Username: {u.username}, Role: {u.role}')