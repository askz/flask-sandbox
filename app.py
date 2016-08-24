from datetime import datetime
from flask import Flask, request, flash, url_for, redirect, render_template, abort, Response
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import json
import hashlib

# Loading Flask
app = Flask(__name__)
# Loading configuration (db file and debugging tools)
app.config.from_pyfile('rest.cfg')
# Loading SQLAlchemy
db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'user'
    """Users table from bdd.db"""

    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    lastname = db.Column(db.String(100), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(40), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    
    def __init__(self, lastname, firstname, email, password, role='normal'):
        self.id = self.query.order_by("id desc").first().id + 1
        self.lastname = lastname
        self.firstname = firstname
        self.email = email
        self.password = password
        self.role = role

    def as_dict(self):
        """Prepare ORM object for serialization"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def check_auth(email, password):
    """This function is called to check if a username /
    password combination is valid. With ugly SHA1, 
    special thanks to the author of the course. (And my lazyness tooo:)"""
    sha = hashlib.sha1()
    sha.update(password)
    user = Users.query.filter_by(email=email).first()
    return user.password == sha.hexdigest()


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return send_msg(
        401,
        'Must be connected',
        headers={'WWW-Authenticate': 'Basic realm="Login Required"'})


''' DECORATORS '''
def requires_auth(f):
    """Decorator for auth required methods"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = request.authorization.username
        user_instance = Users.query.filter_by(email=user).first()
        if user_instance.role != 'admin':
            return send_msg(403, 'Must be admin.')
        return f(*args, **kwargs)

    return decorated


def returns_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        r = f(*args, **kwargs)
        return Response(r, content_type='application/json; charset=utf-8')

    return decorated_function


@app.route('/users', methods=['POST'])
@requires_auth
@requires_admin
def create_user():
    json_data = request.get_json(force=True) 
    d = json_data.get
    try:
        new_user = Users(d('lastname'), d('firstname'), d('email'), d('password'), d('role') or 'normal')
        db.session.add(new_user)
        db.session.commit()
    except Exception as ex:
        # print ex.__dict__
        # print str(ex.__dict__['orig'])[:8]
        if isinstance(ex, IntegrityError) and str(ex.__dict__['orig'])[:8] == "NOT NULL":
            model_keys = Users.__table__.columns.keys()
            if model_keys != json_data.keys():
                missingFields = list(set(model_keys) - set(json_data.keys()))
                missingFields.remove('id')
                return send_msg(400, "Missing fields : " + ', '.join(missingFields), missingFields)
        elif str(ex.__dict__['orig'])[:6] == "UNIQUE":
            return send_msg(400, "User already exists")
        else:
            return send_msg(400, "Unknown error. \nDetails : " + ex.__dict__['orig'])
    return Response(json.dumps(new_user.as_dict()), 201)



def send_msg(code, message, missingFields=[], headers={}):
    error = {'code': code, 'message': message, 'missingFields': missingFields}
    return Response(json.dumps(error), error['code'], headers)

@app.route('/user/<int:id>', methods=['DELETE'])
@requires_auth
@requires_admin
@returns_json
def delete_user(id):
    """Returns one user with matching id."""
    user = Users.query.filter_by(id=id).first()
    if not user:
        return send_msg(404, 'Not Found')
    return send_msg(204, "No data")

@app.route('/user/<int:id>', methods=['PUT'])
@requires_auth
@requires_admin
@returns_json
def update_user(id):
    user = Users.query.filter_by(id=id).first()
    json_data = request.get_json(force=True)
    
    user.update
    db.session.commit()

@app.route('/user/<int:id>', methods=['GET'])
@requires_auth
@requires_admin
@returns_json
def show_user(id):
    """Returns one user with matching id."""
    user = Users.query.filter_by(id=id)
    if not user:
        return send_msg(404, 'Not Found')
    user = user.as_dict()
    user.pop('password')
    return json.dumps(user)

@app.route('/users', methods=['GET'])
@requires_auth
@returns_json
def show_users():
    """List all users"""
    ret = []
    for user in Users.query.all():
        user = user.as_dict()
        user.pop('password')
        ret.append(user)
    return json.dumps(ret)

if __name__ == '__main__':
    app.run()
