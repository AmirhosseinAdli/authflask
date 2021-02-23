from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
# from flask_mysqldb import MySQLdb, MySQL
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from runtime_config import ConfigServer

username = ConfigServer.DB_USERNAME
passwprd = ConfigServer.DB_PASSWORD
url = ConfigServer.DB_URL
schema = ConfigServer.DB_SCHEMA



app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phonebook.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{}:{}@{}/{}'.format(username, passwprd, url, schema)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    date_updated = db.Column(db.DateTime, default=None)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    name = db.Column(db.String(50), unique=True)
    phone_number = db.Column(db.Integer)
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    date_updated = db.Column(db.DateTime, default=None)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'The token is invalid!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {
            'public_id': user.public_id,
            'name': user.name,
            'password': user.password,
            'admin': user.admin
        }
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'There is no user!'})
    user_data = {
        'public_id': user.public_id,
        'name': user.name,
        'password': user.password,
        'admin': user.admin
    }

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'There is no user!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'There is no user!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user deleted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-authenticate': 'Basic_realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-authenticate': 'Basic_realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-authenticate': 'Basic_realm="Login required!"'})


@app.route('/contact', methods=['GET'])
@token_required
def get_all_contacts(current_user):
    contacts = Contact.query.filter_by(user_id=current_user.id).all()

    output = []

    for contact in contacts:
        contact_data = {}
        contact_data['id'] = contact.id
        contact_data['name'] = contact.name
        contact_data['phone_number'] = contact.phone_number
        contact_data['date_created'] = contact.date_created
        contact_data['date_created'] = contact.date_created
        contact_data['date_updated'] = contact.date_updated
        output.append(contact_data)
    return jsonify({'contacts': output})


@app.route('/contact/<contact_id>', methods=['GET'])
@token_required
def get_one_contact(current_user, contact_id):
    contact = Contact.query.filter_by(id=contact_id, user_id=current_user.id).first()

    if not contact:
        return jsonify({'message': 'The contact does not exist!'})
    contact_data = {}
    contact_data['id'] = contact.id
    contact_data['name'] = contact.name
    contact_data['phone_number'] = contact.phone_number
    contact_data['date_created'] = contact.date_created
    contact_data['date_created'] = contact.date_created
    contact_data['date_updated'] = contact.date_updated
    return jsonify({'message': contact_data})


@app.route('/contact', methods=['POST'])
@token_required
def create_contact(current_user):
    data = request.get_json()

    new_contact = Contact(user_id=current_user.id, name=data['name'], phone_number=data['phone_number'],
                          date_created=datetime.datetime.utcnow())
    db.session.add(new_contact)
    db.session.commit()
    return jsonify({'message': 'contact created!'})


@app.route('/contact/<contact_id>', methods=['PUT'])
@token_required
def edit_contact(current_user, contact_id):
    data = request.get_json()
    contact = Contact.query.filter_by(id=contact_id, user_id=current_user.id).first()
    if not contact:
        return jsonify({'message': 'There is no contact by this id!!!'})
    contact.name = data['name']
    contact.phone_number = data['phone_number']
    contact.date_updated = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({'message': 'The contact updated'})


@app.route('/contact/<contact_id>', methods=['DELETE'])
@token_required
def delete_contact(current_user, contact_id):
    contact = Contact.query.filter_by(id=contact_id, user_id=current_user.id).first()
    if not contact:
        return jsonify({'message': 'There is no contact by this id!!!'})
    db.session.delete(contact)
    db.session.commit()
    return jsonify({'message': 'The contact by id={} deleted!'.format(contact.id)})


if __name__ == '__main__':
    app.run(debug=True)
