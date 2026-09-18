from app.extensions import db


class Order(db.Model):
    __tablename__ = "a04_orders"

    id = db.Column(db.Integer, primary_key=True)
    total_cents = db.Column(db.Integer, nullable=False)
    paid = db.Column(db.Boolean, nullable=False, default=False)
