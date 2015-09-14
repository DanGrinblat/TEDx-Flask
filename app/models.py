from app import db, app
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(64))
    first_name = db.Column(db.String(64))
    phone = db.Column(db.String(64))
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    confirmed_at = db.Column(db.DateTime())
    affiliation = db.Column(db.String(64))
    photo_url = db.Column(db.String(120))
	
    #3 days 259200
    def generate_auth_token(self, expiration = 1209600):
        s = Serializer('secret-key', expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer('secret-key')
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.query.get(data['id'])
        return user
    
    def hash_password(self, password):
	    self.password_hash = pwd_context.encrypt(password)
		
    def verify_password(self, password):
	    return pwd_context.verify(password, self.password_hash)

    def __repr__(self):
        return '<User %r>' % (self.last_name + ', ' + self.first_name)