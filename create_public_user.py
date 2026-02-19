from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if public user already exists
    public_user = User.query.filter_by(username='public').first()
    if public_user:
        print(f"Public user already exists with ID: {public_user.id}")
    else:
        # Create public user
        public_user = User(
            employee_id='PUBLIC001',
            username='public',
            email='public@visitor.com',
            password_hash=generate_password_hash('public123'),
            role='public',
            department='Public',
            is_active=True,
            is_hod=False
        )
        db.session.add(public_user)
        db.session.commit()
        print(f"Created public user with ID: {public_user.id}")