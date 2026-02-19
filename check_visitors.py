from app import app, db, Visitor

with app.app_context():
    print('Total visitors:', Visitor.query.count())
    print('Recent visitors:')
    visitors = Visitor.query.order_by(Visitor.id.desc()).limit(5).all()
    for v in visitors:
        print(f'ID: {v.id}, Name: {v.name}, Visitor_ID: {v.Visitor_ID}, Created by: {v.created_by}')