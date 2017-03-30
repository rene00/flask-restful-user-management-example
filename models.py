from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from marshmallow_sqlalchemy import ModelSchema
from app import app


db = SQLAlchemy(app)
session = db.session

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')),
)


class Role(db.Model, RoleMixin):
    __tablename__ = 'role'
    __table_args__ = {'mysql_charset': 'utf8'}

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class UserSchema(ModelSchema):
    class Meta:
        fields = ('id', 'email',)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    __table_args__ = {'mysql_charset': 'utf8'}

    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship(
        'Role', secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )
