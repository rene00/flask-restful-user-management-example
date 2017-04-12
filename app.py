from webargs import fields, validate
from webargs.flaskparser import abort, parser, use_kwargs
from functools import wraps
from flask import (
    Blueprint, Flask, request, redirect, jsonify, url_for,
    after_this_request, render_template_string
)
from flask_mail import Mail
from flask_restful import Resource, Api
from flask_security import (
    SQLAlchemyUserDatastore, Security, AnonymousUser,
    auth_token_required
)
from flask_security.confirmable import (
    generate_confirmation_token, confirm_email_token_status, confirm_user
)
from flask_security.utils import (
    encrypt_password, verify_password, md5, send_mail
)
from flask_security.views import _commit
from flask_login import LoginManager, current_user, logout_user, login_user
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import safe_str_cmp


class Configuration:
    REGISTERABLE = True
    SECRET_KEY = 'femNuccodcutAbAp'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = ('sqlite:///app.db')
    SECURITY_COMFIRMABLE = True
    SECURITY_RECOVERABLE = True
    SECURITY_PASSWORD_HASH = 'bcrypt'
    SECURITY_PASSWORD_SALT = 'CrotbiobmenPibej'
    CONFIRM_REGISTRATION = True
    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    EMAIL_SUBJECT_REGISTER = 'Welcome'
    EMAIL_SUBJECT_CONFIRM = 'Please Confirm'
    SEND_REGISTER_EMAIL = True
    SECURITY_EMAIL_SENDER = 'admin@example.org'

app = Flask(__name__)
app.config.from_object(Configuration)

import models
from models import db

db.create_all()

# plans
for plan_name in ('bronze', 'silver', 'gold'):
    db.session.add(models.Plan(name=plan_name))
    try:
        db.session.commit()
    except (IntegrityError, InvalidRequestError):
        pass

login_manager = LoginManager()
login_manager.init_app(app)

user_datastore = SQLAlchemyUserDatastore(models.db, models.User, models.Role)
security = Security(app, user_datastore, register_blueprint=False)

api = Api(app)

mail = Mail(app)


@parser.error_handler
def handle_request_parsing_error(err):
    abort(422, errors=err.messages)


def unauth_handler():
    abort(401, errors='Unauthorized')


security.unauthorized_handler(unauth_handler)


def check_auth(email, password):
    try:
        user = (
            models.db.session.query(models.User).
            filter_by(email=email).one()
        )
    except NoResultFound:
        return False
    else:
        if not verify_password(password, user.password):
            return False
        else:
            return True


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def authenticate():
    abort(401, message="login required")


def error(status_code, message):
    "API error"
    response = jsonify({'message': message})
    response.status_code = status_code
    return response


def get_user_from_token(token):
    # app = current_app._get_current_object()
    key = app.config['SECRET_KEY']
    salt = app.config['SECURITY_REMEMBER_SALT']
    login_serializer = URLSafeTimedSerializer(key, salt=salt)
    data = login_serializer.loads(token)
    user = user_datastore.find_user(id=data[0])
    if user and safe_str_cmp(md5(user.password), data[1]):
        return user
    return AnonymousUser


def confirm_error():
    return render_template_string('Confirmed Error')


def confirmed():
    return render_template_string('Confirmed Successfully')


def confirm_token(token):
    expired, invalid, user = confirm_email_token_status(token)

    if not user or invalid:
        invalid = True

    if invalid or expired:
        return redirect(url_for('app.confirm_error'))

    if user != current_user:
        logout_user()
        login_user(user)

    if confirm_user(user):
        after_this_request(_commit)

    return redirect(url_for('app.confirmed'))


class Register(Resource):
    post_kwargs = {
        'email': fields.Str(required=True),
        'password': fields.Str(required=True, validate=validate.Length(min=6))
    }

    @use_kwargs(post_kwargs)
    def post(self, email, password):

        if not app.config.get('REGISTERABLE'):
            abort(403, errors='Registration disabled.')

        try:
            models.db.session.query(models.User).filter_by(email=email).one()
        except NoResultFound:
            pass
        else:
            abort(409, errors='Email address already exists.')

        user = user_datastore.create_user(
            email=email,
            password=encrypt_password(password)
        )

        plan = (
            models.db.session.query(models.Plan).
            filter_by(name='bronze').one()
        )
        user.plan = plan

        try:
            db.session.commit()
        except IntegrityError:
            return abort(501, errors='Failed to register.')

        if app.config.get('CONFIRM_REGISTRATION'):
            token = generate_confirmation_token(user)
            confirmation_link = url_for(
                'app.confirm_token', token=token, _external=True
            )
            user.active = False
            if app.config.get('SEND_REGISTER_EMAIL'):
                send_mail(
                    app.config.get('EMAIL_SUBJECT_CONFIRM'),
                    user.email, 'confirmation_instructions', user=user,
                    confirmation_link=confirmation_link
                )

        return models.UserSchema().dump(user)


class Login(Resource):
    @requires_auth
    def get(self):
        auth = request.authorization
        try:
            user = (
                models.db.session.query(models.User).
                filter_by(email=auth.username)
            ).one()
        except NoResultFound:
            abort(401, 'Failed authentication.')
        else:
            token = user.get_auth_token()
        return {'token': token}


class Info(Resource):

    get_kwargs = {
        'token': fields.Str(
            required=True,
            load_from='Authentication-Token',
            location='headers'
        )
    }

    @auth_token_required
    @use_kwargs(get_kwargs)
    def get(self, token):
        user = get_user_from_token(token)
        return models.UserSchema().dump(user)


class Plan(Resource):

    get_kwargs = {
        'plan_id': fields.Int(required=True),
    }

    @use_kwargs(get_kwargs)
    def get(self, plan_id):
        try:
            plan = (
                models.db.session.query(models.Plan).
                filter_by(id=plan_id)
            ).one()
        except NoResultFound:
            return error(404, 'Plan not found.')

        return models.PlanSchema().dump(plan)

api.add_resource(Register, '/account/register')
api.add_resource(Login, '/account/login')
api.add_resource(Info, '/account/info')
api.add_resource(Plan, '/plan')


bp = Blueprint('app', __name__)
bp.route(
    '/confirm/token/<token>', methods=['GET', 'POST'], endpoint='confirm_token'
)(confirm_token)
bp.route(
    '/confirm/success', methods=['GET', 'POST'], endpoint='confirmed'
)(confirmed)
bp.route(
    '/confirm/error', methods=['GET'], endpoint='confirm_error'
)(confirm_error)
app.register_blueprint(bp)
