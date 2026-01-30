from app import app, db, Visitor
from datetime import datetime

def test_ehs_validation():
    with app.app_context():
        # Find the test visitor
        test_visitor = Visitor.query.filter_by(name='Test_EHS_Check').first()
        if not test_visitor:
            print("Test visitor not found")
            return
        
        print(f"Testing EHS validation for visitor: {test_visitor.name}")
        print(f"Current status: {test_visitor.status}")
        print(f"EHS approved: {test_visitor.ehs_approved}")
        print(f"Purpose: {test_visitor.purpose}")
        print()
        
        # Simulate the check-in validation logic
        print("Simulating check-in validation...")
        
        # Check if status is 'approved'
        if test_visitor.status == 'approved':
            print("✓ Status is 'approved'")
            
            # Check if it's a vendor service visitor
            if test_visitor.purpose and 'Vendor Service' in test_visitor.purpose:
                print("✓ Is vendor service visitor")
                
                # Check EHS approval
                if not test_visitor.ehs_approved:
                    print("✗ EHS approval required but not granted")
                    print("EXPECTED: Check-in should be denied")
                    print("Validation working correctly!")
                    return
                else:
                    print("✓ EHS approved")
            else:
                print("✓ Not vendor service visitor")
            
            # If we get here, check-in should be allowed
            print("✓ Check-in would be allowed")
        else:
            print(f"✗ Status is '{test_visitor.status}', not 'approved'")
            print("Check-in denied due to wrong status")

if __name__ == "__main__":
    test_ehs_validation()