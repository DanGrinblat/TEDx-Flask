from flask import Flask, send_file, Response, stream_with_context, make_response
from flask_admin import Admin
from flask_admin.base import expose
from flask_admin.tools import rec_getattr
import flask_admin.model.base
from flask.ext import admin, login
from flask_login import current_user
from flask_admin.contrib.sqla import ModelView
from flask.ext.sqlalchemy import SQLAlchemy

from flask_admin.helpers import get_redirect_target
from flask_admin._compat import iteritems
from werkzeug import secure_filename

from io import StringIO
import flask_wtf, csv, time
#from pandas import DataFrame

#app = Flask(__name__, static_url_path='')
app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
flask_wtf.CsrfProtect(app)

#from app import user
from app import api, models
admin = Admin(app, name='TEDxCSU Admin', template_mode='bootstrap3')

class AdminModelView(ModelView): #CSRF Protection
    form_base_class = flask_wtf.Form

class UserView(ModelView):
    column_display_pk = True
    column_exclude_list = ['password_hash']
    column_searchable_list = ['last_name', 'email']
    form_excluded_columns = ['password_hash']
    can_create = False
    can_export = True

    export_max_rows = None
    export_columns = ['id', 'last_name', 'first_name', 'phone', 'email', 'affiliation', 'photo_url']

    def _get_data_for_export(self):
        view_args = self._get_list_extra_args()

        # Map column index to column name
        sort_column = self._get_column_by_idx(view_args.sort)
        if sort_column is not None:
            sort_column = sort_column[0]

        _, query = self.get_list(view_args.page, sort_column, view_args.sort_desc, view_args.search,
                                 view_args.filters, execute=False)

        return query.limit(None).all()

    def get_export_csv(self):
        self.export_columns = self.export_columns or [column_name for column_name, _ in self._list_columns]

        io = StringIO()
        rows = csv.DictWriter(io, self.export_columns)

        data = self._get_data_for_export()

        rows.writeheader()

        for item in data:
            row = {column: rec_getattr(item, column) for column in self.export_columns}
            print(row)
            rows.writerow(row)

        io.seek(0)
        return io.getvalue()

    @expose('/export')
    def export(self):
        response = make_response(self.get_export_csv())
        response.mimetype = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=%s.csv' % self.name.lower().replace(' ', '_')

        return response
    #def is_accessible(self):
    #    return login.current_user.is_authenticated()
    #def inacccessible_callback(self, name, **kwargs):
    #    return redirect(url_for('login', next=request.url))

admin.add_view(UserView(models.User, db.session))