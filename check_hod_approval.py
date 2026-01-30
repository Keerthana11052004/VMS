from app import app, db, Visitor, User

with app.app_context():
    # Find the visitor
    v = Visitor.query.filter_by(Visitor_ID='67698').first()
    if not v:
        print("Visitor not found")
        exit()
    
    print(f"Visitor approved_by_id: {v.approved_by_id}")
    print(f"Visitor ehs_approved: {v.ehs_approved}")
    print(f"Visitor ehs_approved_by_id: {v.ehs_approved_by_id}")
    print(f"Visitor status: {v.status}")
    print(f"Visitor purpose: {v.purpose}")
    
    # Find the host
    host = User.query.get(v.host_id) if v.host_id else None
    print(f"Host username: {host.username if host else 'N/A'}")
    print(f"Host department: {host.department if host else 'N/A'}")
    
    # Find the HOD for this department
    hod = User.query.filter_by(department=host.department if host else 'General', is_hod=True, is_active=True).first() if host else None
    print(f"HOD username: {hod.username if hod else 'N/A'}")
    print(f"HOD user ID: {hod.id if hod else 'N/A'}")
    
    # Check if they're the same
    print(f"Same user? {v.approved_by_id == (hod.id if hod else None)}")
    
    # Check the approval dashboard query logic
    print("\nChecking approval dashboard logic:")
    print(f"Visitor.status == 'approved': {v.status == 'approved'}")
    print(f"'vendor service' in purpose.lower(): {'vendor service' in v.purpose.lower()}")
    print(f"ehs_approved == True: {v.ehs_approved == True}")
    print(f"approved_by_id != hod.id: {v.approved_by_id != (hod.id if hod else None)}")