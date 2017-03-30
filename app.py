from webargs import fields, validate
from webargs.flaskparser import abort, parser, use_kwargs
from functools import wraps
from flask import Flask, request
from flask_restful import Resource, Api
from flask_security import (
    SQLAlchemyUserDatastore, Security, AnonymousUser,
    auth_token_required
)
from flask_security.utils import encrypt_password, verify_password, md5
from flask_login import LoginManager
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError


class Configuration:
    SECRET_KEY = 'femNuccodcutAbAp'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = ('sqlite:///app.db')
    SECURITY_PASSWORD_HASH = 'bcrypt'
    SECURITY_PASSWORD_SALT = 'CrotbiobmenPibej'

app = Flask(__name__)
app.config.from_object(Configuration)

import models
from models import db

db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

user_datastore = SQLAlchemyUserDatastore(models.db, models.User, models.Role)
security = Security(app, user_datastore, register_blueprint=False)

api = Api(app)


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


from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import safe_str_cmp


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


class Register(Resource):
    post_kwargs = {
        'email': fields.Str(required=True),
        'password': fields.Str(required=True, validate=validate.Length(min=6))
    }

    @use_kwargs(post_kwargs)
    def post(self, email, password):
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
        try:
            db.session.commit()
        except IntegrityError:
            return abort(501, errors='Failed to register.')
        else:
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


api.add_resource(Register, '/account/register')
api.add_resource(Login, '/account/login')
api.add_resource(Info, '/account/info')