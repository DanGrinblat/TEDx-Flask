import os
from flask import Flask, jsonify, abort, make_response, request, g
from flask.ext.restful import Api, Resource, reqparse, fields, marshal
from flask.ext.httpauth import HTTPBasicAuth
from datetime import datetime
from app import app, db, models
from werkzeug import secure_filename
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

api = Api(app)
auth = HTTPBasicAuth()

@app.route('/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ 'name': g.user.first_name, 'token': token.decode('ascii') })

@auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    user = models.User.verify_auth_token(email_or_token)
    if not user:
        # try to authenticate with email/password
        user = models.User.query.filter_by(email = email_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

#Use for database reset
#@auth.get_password
#def get_password(username):
#    if username == 'miguel':
#        return 'python'
#    return None

@auth.error_handler
def unauthorized():
    # return 401
    return make_response(jsonify({'message': 'Unauthorized access'}), 401)

#Fields that are sent back
user_fields = {
    'email': fields.String,
    'id': fields.Integer,
    'first_name': fields.String,
    'last_name': fields.String,
    'phone': fields.String,
    'confirmed_at': fields.String,
    'affiliation': fields.String,
    'photo_url': fields.String
    #'uri': fields.Url('user')
}

class UserListAPI(Resource):
    decorators = [auth.login_required]
    
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        #self.reqparse.add_argument('intent', type=str, required=True,
        #                           help='No intent provided',
        #                           location='json')
        self.reqparse.add_argument('email', type=str, required=True,
                                   help='No e-mail address provided',
                                   location='json')
        self.reqparse.add_argument('password', type=str, required=True,
                                   help='No password provided',
                                   location='json')
        self.reqparse.add_argument('first_name', type=str, required=True,
                                   help='No first name provided',
                                   location='json')
        self.reqparse.add_argument('last_name', type=str, required=True,
                                   help='No last name provided',
                                   location='json')
        self.reqparse.add_argument('phone', type=str, required=True,
                                   help='No phone number provided',
                                   location='json')
        self.reqparse.add_argument('affiliation', type=str, required=True,
                                   help='No affiliation provided',
                                   location='json')
        self.reqparse.add_argument('confirmed_at', type=str, default="",
                                   location='json')
        self.reqparse.add_argument('photo', type=werkzeug.datastructures.FileStorage, required=False,
                                    location='files')
        super(UserListAPI, self).__init__()

    #def get(self):
    #    return {'users': [marshal(user, user_fields) for user in users]}

    #You can ONLY register with user (id 1).
    #You cannot make an account with duplicate email.
    def post(self):
        args = self.reqparse.parse_args()
        photo = args['photo']
        unique_email = args['email']
        user = models.User.query.filter_by(id = '1').first()
        if g.user is not user:
            return make_response(jsonify({'message': 'Unauthorized access'}), 401)
        elif models.User.query.filter_by(email = unique_email).first():
            return make_response(jsonify({'message': 'E-mail already exists'}), 409)
        else:
            user = models.User(email = unique_email,
                first_name = args['first_name'],
                last_name = args['last_name'],
                phone = args['phone'],
                affiliation = args['affiliation'],
                confirmed_at = datetime.utcnow()
            )
            user.hash_password(args['password'])
            if photo is not None:
                if allowed_file(photo.filename):
                    filename = secure_filename(photo.filename)
                    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    photo.save(file_path)
                    user.photo_url = file_path
            db.session.add(user)
            db.session.commit()
            return marshal(user, user_fields), 201

class UserAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('first_name', type=str, required = False, location='json')
        self.reqparse.add_argument('last_name', type=str, required = False, location='json')
        self.reqparse.add_argument('password', type=str, required = False, location='json')
        self.reqparse.add_argument('phone', type=str, required = False, location='json')
        self.reqparse.add_argument('email', type=str, required = False, location='json')
        self.reqparse.add_argument('affiliation', type=str, required = False, location='json')
        self.reqparse.add_argument('old_password', type=str, required = False, location='json')
        self.reqparse.add_argument('photo', type=werkzeug.datastructures.FileStorage, required=False,
                                    location='files')
        super(UserAPI, self).__init__()

    def get(self):
        return {'user': marshal(g.user, user_fields)}

    def put(self):
    #Error check for duplicate email given
        args = self.reqparse.parse_args()
        user = models.User.query.get(g.user.id)
        new_unique_email = args['email']
        new_password = args['password']
        old_password = args['old_password']
        if old_password is None:
            return make_response(jsonify({'message': 'No password entered'}), 401)
        if user.verify_password(old_password):
            if models.User.query.filter_by(email = new_unique_email).first():
                return make_response(jsonify({'message': 'E-mail already exists'}), 409)
            for i in user_fields:
                if i in args:
                    setattr(user, i, args[i])
            if new_password is not None:
                user.hash_password(args['password'])
            file = request.files['file']
            #NEW photo upload
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                user.photo_url = file_path
               
            db.session.commit()
            return marshal(user, user_fields), 201
        else:
            return make_response(jsonify({'message': 'Unauthorized access'}), 401)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']
            
@app.route('/api/v1.0/user/photo', methods=['GET', 'POST'])
@auth.login_required
def upload():
    user = models.User.query.get(g.user.id)
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user.photo_url = file_path
            db.session.commit()
            return make_response(jsonify({'photo_url':file_path}), 200)
        return make_response(jsonify({'message':'Invalid file'}), 400)
    else:
        return make_response(jsonify({'photo_url':user.photo_url}), 200)

api.add_resource(UserListAPI, '/api/v1.0/users', endpoint = 'users')
api.add_resource(UserAPI, '/api/v1.0/user', endpoint = 'user')