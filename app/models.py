from flask import current_app
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, login_manager


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {'User': ( Permission.MAKE_LIST, True),
                 'SuperUser' : ( Permission.MAKE_LIST | Permission.EDIT_DB, False),
                 'Administrator' : (0xFF, False)
                 }

        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, permissions):
        return self.role is not None and \
                (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Permission:
    EDIT_DB = 0x01
    MAKE_LIST = 0x02
    ADMINISTER = 0x80

class LabcytePicklist(db.Model):
    #this is the details for the liquid transfer
    __tablename__ = 'labcyte_picklist'
    id = db.Column(db.Integer, primary_key=True)
    unique_job_id = db.Column(db.String(64), unique=False, index=True)
    user_name = db.Column(db.String(64), unique=False, index=True)
    transfer_id = db.Column(db.Integer, unique=False, index=True)
    source_well_id = db.Column(db.String(64), unique=False, index=True)
    source_barcode = db.Column(db.String(64), unique=False, index=True)
    destination_well_id = db.Column(db.String(64), unique=False, index=True)
    destination_plate_barcode = db.Column(db.String(64), unique=False, index=True)
    source_plate_number = db.Column(db.Integer, unique=False, index=True)
    destination_plate_number = db.Column(db.Integer, unique=False, index=True)
    transfer_volume = db.Column(db.Integer, unique=False, index=True)
    liquid_class = db.Column(db.String(64), unique=False, index=True)
    source_plate_type = db.Column(db.Integer, unique=False, index=True)
    destination_plate_type = db.Column(db.Integer, unique=False, index=True)

class JobInformation(db.Model):
    #this is the details for the liquid transfer
    __tablename__ = 'job_information'
    id = db.Column(db.Integer, primary_key=True)
    unique_job_id = db.Column(db.String(64), unique=False, index=True)
    user_name = db.Column(db.String(64), unique=False, index=True)
    number_of_source_plates = db.Column(db.Integer, unique=False, index=True)
    number_of_destination_plates = db.Column(db.Integer, unique=False, index=True)
    echo_type = db.Column(db.String(64), unique=False, index=True)

class LiquidClasses(db.Model):
    __tablename__ = 'liquid_classes'
    id = db.Column(db.Integer, primary_key=True)
    echo_type = db.Column(db.String(64), unique=False, index=True)
    liquid_class_name = db.Column(db.String(64), unique=False, index=True)
    liquid_class_number = db.Column(db.Integer, unique=False, index=True)

class SourcePlateTypes(db.Model):
    __tablename__ = 'source_plate_types'
    id = db.Column(db.Integer, primary_key=True)
    echo_type = db.Column(db.String(64), unique=False, index=True)
    source_plate_name = db.Column(db.String(64), unique=False, index=True)
    source_plate_number = db.Column(db.Integer, unique=False, index=True)
    number_of_wells = db.Column(db.Integer, unique=False, index=True)
    number_of_rows = db.Column(db.Integer, unique=False, index=True)
    number_of_columns = db.Column(db.Integer, unique=False, index=True)

class DestinationPlateTypes(db.Model):
    __tablename__ = 'destination_plate_types'
    id = db.Column(db.Integer, primary_key=True)
    echo_type = db.Column(db.String(64), unique=False, index=True)
    source_plate_name = db.Column(db.String(64), unique=False, index=True)
    source_plate_number = db.Column(db.Integer, unique=False, index=True)
    number_of_wells = db.Column(db.Integer, unique=False, index=True)
    number_of_rows = db.Column(db.Integer, unique=False, index=True)
    number_of_columns = db.Column(db.Integer, unique=False, index=True)

class WellIds(db.Model):
    __tablename__ = 'well_ids'
    id = db.Column(db.Integer, primary_key=True)
    row_letter = db.Column(db.String(64), unique=False, index=True)
    column_number = db.Column(db.Integer, unique=False, index=True)
    well_number = db.Column(db.Integer, unique=False, index=True)
    well_id = db.Column(db.String(64), unique=False, index=True)
    plate_name = db.Column(db.String(64), unique=False, index=True)
    total_number_wells = db.Column(db.Integer, unique=False, index=True)