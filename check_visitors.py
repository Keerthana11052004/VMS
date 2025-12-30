from app import app, db, Visitor

with app.app_context():
    visitors = Visitor.query.all()
    for v in visitors:
        print(f'ID: {v.Visitor_ID}, Name: {v.name}, Purpose: {v.purpose}, Work Permit: {v.work_permit_certificate}')