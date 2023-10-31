from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.String(20), primary_key=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)

    feedback = relationship('Feedback', back_populates='user')

    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """ Hash the password before storing it in the database """

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = cls(
                        username=username, 
                        password=password_hash, 
                        email=email, 
                        first_name=first_name, 
                        last_name=last_name
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user
    
    @classmethod
    def authenticate(cls, username, password):
        """ Checking for the username and password in the database """

        user = cls.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return None

class Feedback(db.Model):
    __tablename__= "feedback"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(20), db.ForeignKey('users.username'), nullable=False)

    user = relationship('User', back_populates='feedback', foreign_keys=[username])

    def __init__(self, title, content, username):
        self.title = title
        self.content = content
        self.username = username
