import os
basedir = os.path.abspath(os.path.dirname(__file__))
apidir = os.path.join(basedir, 'api', 'v1.0')

#Security key for sessions and CSRF Protection
SECRET_KEY = '9heE4$@:-*RLQ"7%'
CSRF_ENABLED = True

#Create paths for ease of use
UPLOAD_FOLDER = os.path.join(apidir, 'user_photos')
GALLERY_FOLDER = os.path.join(apidir, 'photo_gallery')
SPEAKER_FOLDER = os.path.join(apidir, 'event_details/speakers')
BIOS_FOLDER = os.path.join(apidir, 'event_details/speakers/bios')
TENTS_FOLDER = os.path.join(apidir, 'event_details/tents')
ITINERARY_FOLDER = os.path.join(apidir, 'event_details/itinerary')
IMAGE_DIR = '/api/v1.0/user_photos'

#File upload extensions allowed
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

#SQLAlchemy setup
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')