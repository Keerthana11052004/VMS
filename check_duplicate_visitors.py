from app import app, db, Visitor

with app.app_context():
    # Get all visitors with Visitor_ID 45974
    visitors = Visitor.query.filter_by(Visitor_ID='45974').all()
    
    print(f"Found {len(visitors)} visitors with Visitor_ID 45974:")
    print("-" * 50)
    
    for visitor in visitors:
        print(f"ID: {visitor.id}")
        print(f"Name: {visitor.name}")
        print(f"Email: {visitor.email}")
        print(f"Mobile: {visitor.mobile}")
        print(f"Created by: {visitor.created_by}")
        print(f"Status: {visitor.status}")
        print("-" * 30)