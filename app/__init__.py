from flask import Flask
from flask_admin import Admin
from flask.ext import admin, login
from flask_login import current_user
from flask_admin.contrib.sqla import ModelView
from flask.ext.sqlalchemy import SQLAlchemy
import flask_wtf

#app = Flask(__name__, static_url_path='')
app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
flask_wtf.CsrfProtect(app)

#from app import user
from app import api, models
admin = Admin(app, name='TEDxCSU Admin', template_mode='bootstrap3')
admin.add_view(ModelView(models.User, db.session))


class AdminModelView(ModelView): #CSRF Protection
    form_base_class = flask_wtf.Form
    
    #def is_accessible(self):
    #    return login.current_user.is_authenticated()
    #def inacccessible_callback(self, name, **kwargs):
    #    return redirect(url_for('login', next=request.url))