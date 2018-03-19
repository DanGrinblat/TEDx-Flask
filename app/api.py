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
import re
import json
api = Api(app)
auth = HTTPBasicAuth()

@app.route('/')
def hello_world():
    return render_template('index.html')

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
}

class UserListAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
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
        self.reqparse.add_argument('confirmed_at', type=str, default="", required=False,
                                   location='json')
        super(UserListAPI, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()
        unique_email = args['email']
        user = models.User.query.filter_by(id = '1').first()
        if g.user is not user:
            return make_response(jsonify({'message': 'Unauthorized access.'}), 401)
        elif models.User.query.filter_by(email = unique_email).first():
            return make_response(jsonify({'message': 'E-mail already exists.'}), 409)
        else:
            dt = datetime.utcnow()
            user = models.User(email = unique_email,
                first_name = args['first_name'],
                last_name = args['last_name'],
                phone = args['phone'],
                affiliation = args['affiliation'],
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
            user.poll_voted = False #Sets user's vote status to false

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

            file_url_path = os.path.join(app.config['IMAGE_DIR'], filename)
            user.photo_url = file_url_path

            db.session.commit()
            return jsonify({'photo_url':file_url_path})
        return make_response(jsonify({'message': 'Invalid file.'}), 400)
    else:
        return jsonify({'photo_url': user.photo_url})

@app.route('/api/v1.0/event_details/speakers/bios', methods=['GET'])
@auth.login_required
def speaker_bios():
    path = '/api/v1.0/event_details/speakers/bios'
    files = os.listdir(basedir + path)
    children = []
    structure = {}

    for file in files:
        file_path = os.path.join(app.config['BIOS_FOLDER'], file).replace("\\","/")
        with open(file_path, "r",encoding="utf8", errors='replace') as current_file:
            children.append({"name": file,
                            "bio": current_file.read()})
    structure["file_list"] = children
    return jsonify(structure)

@app.route('/api/v1.0/event_details/tents', methods=['GET'])
@auth.login_required
def tents():
    path = '/api/v1.0/event_details/tents'
    files = os.listdir(basedir + path)
    children = []
    structure = {}

    for file in files:
        file_path = os.path.join(app.config['TENTS_FOLDER'], file).replace("\\","/")
        with open(file_path, "r") as current_file:
            children.append({"name": file,
                            "description": current_file.read()})
    structure["file_list"] = children
    return jsonify(structure)

@app.route('/api/v1.0/event_details/itinerary', methods=['GET'])
@auth.login_required
def itinerary():
    path = '/api/v1.0/event_details/itinerary'
    files = os.listdir(basedir + path)
    children = []
    structure = {}

    for file in files:
        file_path = os.path.join(app.config['ITINERARY_FOLDER'], file).replace("\\","/")
        with open(file_path, "r") as current_file:
            children.append({"name": file,
                            "description": current_file.read()})
    structure["file_list"] = children
    return jsonify(structure)

@app.route('/api/v1.0/photo_gallery', methods=['GET'])
@auth.login_required
def img_list():
    path = '/api/v1.0/photo_gallery/'
    files = os.listdir(basedir + path)
    return jsonify({'file_list': files})

@app.route('/api/v1.0/event_details/speakers', methods=['GET'])
@auth.login_required
def speaker_list():
    path = '/api/v1.0/event_details/speakers/'
    file_list = []
    for fname in os.listdir(basedir + path):
        if '.' not in fname:  #Filters out directories
            continue
        file_list.append(fname)
    return jsonify({'file_list': file_list})

@app.route('/api/v1.0/poll', methods=['GET'])
@auth.login_required
def poll_view(): #Return poll question and choices
    path = '/api/v1.0/poll'
    children = []
    structure = {}
    for file in os.listdir(basedir + path):
        file_path = os.path.join(app.config['POLL_FOLDER'], file).replace("\\","/")
        with open(file_path, "r") as f:
            lines = list(f)

    children.append({"question": lines[0].rstrip('\n')})
    for x in range(1, len(lines)):
        children.append({"choice_" + str(x): lines[x].rstrip('\n')})

    structure["poll"] = children
    return jsonify(structure)

@app.route('/api/v1.0/poll/<int:choice>', methods=['GET'])
@auth.login_required
def poll_vote(choice):
    path = '/api/v1.0/poll'
    user = models.User.query.get(g.user.id)
    if (user.poll_voted != True):
        lines = []
        for file in os.listdir(basedir + path):
            file_path = os.path.join(app.config['POLL_FOLDER'], file).replace("\\","/")
            with open(file_path, "r") as infile:
                for line in infile:
                    lines.append(line)
                    
        if (1 <= choice < len(lines)):
            lines[choice] = re.sub('(\d+)(?!\d)', lambda x: str(int(x.group(0)) + 1), lines[choice])
            with open(file_path, 'w') as outfile:
                for line in lines:
                    outfile.write(line)
            #user.poll_voted = True
            return jsonify({'message': 'You have successfully voted on the poll.'})
        else:
            return make_response(jsonify({'message': 'Invalid choice.'}), 400)
    else:
        return make_response(jsonify({'message': 'You have already voted on this poll.'}), 400)
        
@app.route('/api/v1.0/event_details/speakers/<path:filename>', methods=['GET'])
def speaker_access(filename):
    return send_from_directory(app.config['SPEAKER_FOLDER'], filename)

@app.route('/api/v1.0/photo_gallery/<path:filename>', methods=['GET'])
def photo_gallery_access(filename):
    return send_from_directory(app.config['GALLERY_FOLDER'], filename)#jsonify({'img_list': files})

@app.route('/api/v1.0/user_photos/<path:filename>', methods=['GET'])
def user_photos_access(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/v1.0/countdown', methods=['GET'])
def get_date():
    return jsonify({'timestamp': '1445022000000'}) #October 16, 2015 3:00PM

api.add_resource(UserListAPI, '/api/v1.0/users', endpoint = 'users')
api.add_resource(UserAPI, '/api/v1.0/user', endpoint = 'user')