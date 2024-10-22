from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import generate_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('User', 'Admin'), default='User')
    
    def set_password(self, password):
        self.password = generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
        
class Review(db.Model):
    review_id = db.Column(db.Integer, primary_key=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False)