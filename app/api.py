import os
from flask import Flask, jsonify, abort, make_response, request, g, send_from_directory, render_template, redirect
from flask.ext.restful import Api, Resource, reqparse, fields, marshal
from flask.ext.httpauth import HTTPBasicAuth
from datetime import datetime
from app import app, db, models
from config import basedir
from werkzeug import secure_filename
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask.ext.basicauth import BasicAuth

api = Api(app)
auth = HTTPBasicAuth()

app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = 'admin'

basic_auth = BasicAuth(app)

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/admin')
@basic_auth.required
def admin_view():
    return redirect('/admin/')

@app.route('/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return make_response(jsonify( marshal(g.user, user_fields), token=token.decode('ascii') ), 200)

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
    return make_response(jsonify({'message': 'Unauthorized access.'}), 401)

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
        super(UserListAPI, self).__init__()

    #def get(self):
    #    return {'users': [marshal(user, user_fields) for user in users]}

    #You can ONLY register with user (id 1).
    #You cannot make an account with duplicate email.
    def post(self):
        args = self.reqparse.parse_args()
        unique_email = args['email']
        user = models.User.query.filter_by(id = '1').first()
        if g.user is not user:
            return make_response(jsonify({'message': 'Unauthorized access.'}), 401)
        elif models.User.query.filter_by(email = unique_email).first():
            return make_response(jsonify({'message': 'E-mail already exists.'}), 409)
        else:
            user = models.User(email = unique_email,
                first_name = args['first_name'],
                last_name = args['last_name'],
                phone = args['phone'],
                affiliation = args['affiliation'],
                dt = datetime.utcnow(),
                confirmed_at = dt.replace(microsecond = 0)
            )
            user.hash_password(args['password'])
            db.session.add(user)
            db.session.commit()
            return make_response(jsonify( marshal(user, user_fields), photo_url='user/photo'), 201)

class UserAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('first_name', type=str, required = False, location='json')
        self.reqparse.add_argument('last_name', type=str, required = False, location='json')
        self.reqparse.add_argument('new_password', type=str, required = False, location='json')
        self.reqparse.add_argument('phone', type=str, required = False, location='json')
        self.reqparse.add_argument('email', type=str, required = False, location='json')
        self.reqparse.add_argument('affiliation', type=str, required = False, location='json')
        self.reqparse.add_argument('old_password', type=str, required = False, location='json')
        super(UserAPI, self).__init__()

    def get(self):
        return {'user': marshal(g.user, user_fields)}

    def put(self):
    #Error check for duplicate email given
        args = self.reqparse.parse_args()
        user = models.User.query.get(g.user.id)
        new_unique_email = args['email']
        new_password = args['new_password']
        old_password = args['old_password']
        if old_password is None:
            return make_response(jsonify({'message': 'No password entered.'}), 401)
        if user.verify_password(old_password):
            if new_unique_email is not None:
                if models.User.query.filter_by(email = new_unique_email).first():
                    return make_response(jsonify({'message': 'E-mail already exists.'}), 409)
            for i in user_fields:
                if i in args:
                    if args[i] is not None:
                        setattr(user, i, args[i])
            if new_password is not None:
                user.hash_password(new_password)

            db.session.commit()
            return make_response(jsonify(marshal(user, user_fields)), 200)
        else:
            return make_response(jsonify({'message': 'Password incorrect.'}), 401)

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
            extension = file.filename.rsplit('.', 1)[1]
            sequence = (str(user.id), '.', extension)
            filename = ''.join(sequence)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user.photo_url = file_path

            db.session.commit()
            return jsonify({'photo_url':file_path})
        return make_response(jsonify({'message': 'Invalid file.'}), 400)
    else:
        return jsonify({'photo_url': user.photo_url})

@app.route('/api/v1.0/photo_gallery', methods=['GET'])
@auth.login_required
def img_list():
    path = '/api/v1.0/photo_gallery/'
    files = os.listdir(basedir + path)
    return jsonify({'img_list': files})

@app.route('/api/v1.0/event_details/speakers', methods=['GET'])
@auth.login_required
def speaker_list():
    path = '/api/v1.0/event_details/speakers/'
    files = os.listdir(basedir + path)
    return jsonify({'img_list': files})

@app.route('/api/v1.0/event_details/speakers/<path:filename>', methods=['GET'])
def speaker_access(filename):
    return send_from_directory(app.config['SPEAKER_FOLDER'], filename)

@app.route('/api/v1.0/photo_gallery/<path:filename>', methods=['GET'])
def photo_gallery_access(filename):
    return send_from_directory(app.config['GALLERY_FOLDER'], filename)#jsonify({'img_list': files})

@app.route('/api/v1.0/countdown', methods=['GET'])
def get_date():
    return jsonify({'timestamp': '1445022000000'}) #October 16, 2015 3:00PM

api.add_resource(UserListAPI, '/api/v1.0/users', endpoint = 'users')
api.add_resource(UserAPI, '/api/v1.0/user', endpoint = 'user')