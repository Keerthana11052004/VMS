from app import app, db, User

with app.app_context():
    users = User.query.all()
    print('Users in database:')
    for u in users:
        print(f'ID: {u.id}, Username: {u.username}, Email: {u.email}, Role: {u.role}, Department: {u.department}, Is_HOD: {u.is_hod}')