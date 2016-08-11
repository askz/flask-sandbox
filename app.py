from datetime import datetime
from flask import Flask, request, flash, url_for, redirect, \
     render_template, abort, Response
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import json, hashlib

app = Flask(__name__)
app.config.from_pyfile('rest.cfg')
db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = 'user'
    id = db.Column('id', db.Integer, primary_key=True)
    lastname = db.Column(db.String(100))
    firstname = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(40))
    role = db.Column(db.String(10))

    def as_dict(self):
        """Prepare SQLAlchemy object for serialization"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

def check_auth(email, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    sha_1 = hashlib.sha1()
    sha_1.update(password)
    user = Users.query.filter_by(email=email).first()
    return user.password == sha_1.hexdigest() 

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

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
        user = request.environ.get('REMOTE_USER')
        user_instance = Users.query.filter_by(email=user)
        if user_instance.role != 'admin':
            return send_error(403, 'Must be admin')
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
def create_user(): 
    pass

def send_error(code, message, missingFields=[]):
    error = {'code': code, 'message': message}
    if missingFields:
        error['missingFields'] = missingFields.join(' ')
    return json.dumps(error)

@app.route('/user/<int:id>', methods=['GET'])
@requires_auth
@requires_admin
@returns_json
def show_user(id):
    """Returns one user with matching id."""
    user = Users.query.filter_by(id=id).first()
    if not user:
        return send_error(404, 'Not Found')
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
