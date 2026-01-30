from app import app, db, Visitor
from datetime import datetime

with app.app_context():
    # Check Test2 visitor
    v = Visitor.query.filter_by(Visitor_ID='51764').first()
    if v:
        print("=== Test2 Visitor ===")
        print(f"Name: {v.name}")
        print(f"Status: {v.status}")
        print(f"EHS Approved: {v.ehs_approved}")
        print(f"EHS Approved value: {repr(v.ehs_approved)}")
        print(f"EHS Approved type: {type(v.ehs_approved)}")
        print(f"not ehs_approved: {not v.ehs_approved}")
        print(f"Purpose: {v.purpose}")
        print(f"Work Permit: {v.work_permit_certificate}")
        print(f"Safety Measures: {v.safety_measures_checklist}")
        print(f"Check-in Time: {v.check_in_time}")
        print(f"Approved At: {v.approved_at}")
        print(f"EHS Approved At: {v.ehs_approved_at}")
        print()
    else:
        print("Test2 Visitor not found")
    
    # Create a test visitor who is approved but not EHS approved
    test_visitor = Visitor.query.filter_by(name='Test_EHS_Check').first()
    if not test_visitor:
        print("Creating test visitor for EHS validation check...")
        # Find a host user
        from app import User
        host = User.query.first()
        if host:
            test_visitor = Visitor(
                name='Test_EHS_Check',
                email='test@violintec.com',
                mobile='1234567890',
                purpose='Vendor Service - Test EHS',
                host_id=host.id,
                created_by=host.id,
                unit='Unit-1',
                status='approved',
                approved_at=datetime.now(),
                Visitor_ID='EHS_TEST_001',
                work_permit_certificate='test_work_permit.jpg',
                safety_measures_checklist='test_safety_checklist.jpg',
                ehs_approved=False
            )
            db.session.add(test_visitor)
            db.session.commit()
            print("Test visitor created successfully")
        else:
            print("No host user found to create test visitor")
    else:
        print("Test visitor already exists")
        print(f"Test visitor status: {test_visitor.status}")
        print(f"Test visitor EHS approved: {test_visitor.ehs_approved}")