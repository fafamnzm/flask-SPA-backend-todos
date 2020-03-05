import os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'afsdhjluera?!)&%yhlkvzxvc!&%#21398'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')

db = SQLAlchemy(app)
ma = Marshmallow(app)

# Models
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(200))
    completed = db.Column(db.Boolean)
    # user_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def __repr__(self):
        return self.id

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    todos = db.relationship('Todo', backref='user', lazy=True)
    
    def __repr__(self):
        return self.name


# Schema
class TodoSchema(ma.Schema):
    class Meta:
        fields = ('id', 'body', 'completed', 'user_id')

todo_schema = TodoSchema()
todos_schema = TodoSchema(many=True)

class UserSChema(ma.Schema):
    
    todos = ma.Nested(TodoSchema, many=True)
    
    class Meta:
        fields = ('id' ,'public_id', 'name', 'email', 'password', 'admin', 'todos' )

user_schema = UserSChema()
users_schema = UserSChema(many=True)


# Token handling
def token_check(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'msg' : 'No Token'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'msg' : 'Invalid Token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# our routes

@app.route('/user', methods=['POST'])
@token_check
def create_user(current_user):
    
    if not current_user.admin:
        return jsonify({'msg' : 'Only admin allows to do this'})
    
    data = request.get_json()
    hashed_pswrd = generate_password_hash(data['password'], method='sha256')
    # new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pswrd, admin=False)
    public_id = str(uuid.uuid4())
    name = data['name']
    password = hashed_pswrd
    email = data['email']
    
    new_user = User(public_id = public_id , name = name , password = password, email = email, admin = False)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({ 'msg': 'New user created' })

@app.route('/user', methods=['GET'])
@token_check
def get_all_users(current_user):
    # if not current_user.admin:
    #     return jsonify({'msg' : 'Only admin allows to do this'})

    all_users = User.query.all()
    result = users_schema.dump(all_users)
    
    return jsonify(result)

@app.route('/user/<public_id>', methods=['GET'])
@token_check
def get_single_user(current_user ,public_id):
    if not current_user.admin:
        return jsonify({'msg' : 'Only admin allows to do this'})

    # if you want to use id
    # user = User.query.get(id)
    
    # for security reasons, we use public id
    user = User.query.filter_by(public_id = public_id).first()
    # get the first element since it returns a list
    if not user:
        return jsonify({ "msg" : "no user found" })
    return user_schema.jsonify(user)


@app.route('/user/<public_id>', methods=['PUT'])
@token_check
def update_user(current_user ,public_id):
    if not current_user.admin:
        return jsonify({'msg' : 'Only admin allows to do this'})

    # if you want to use id
    # user = User.query.get(id)
    
    # for security reasons, we use public id
    user = User.query.filter_by(public_id = public_id).first()
    # if not user:
    #     return jsonify({ "msg" : "no user found" })
    
    data = request.get_json()
    hashed_pswrd = generate_password_hash(data['password'], method='sha256')
    # user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pswrd, admin=False)
    user.name = data['name']
    user.password = hashed_pswrd    
    
    db.session.commit()
    
    return user_schema.jsonify(user)

@app.route('/user/<public_id>', methods=['DELETE'])
@token_check
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'msg' : 'Only admin allows to do this'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({ "msg" : "no user with this public id found" })
    db.session.delete(user)
    db.session.commit()
    return jsonify({ "msg" : "User succcesfully deleted" })

@app.route('/login')
#no token check here!
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could n\'t verify', 401, {"WWW-Authenticate" : 'Basic realm="Login Required"'})
    
    user = User.query.filter_by(name=auth.username).first()
    
    if not user:
        return make_response('Could n\'t verify', 401, {"WWW-Authenticate" : 'Basic realm="Login Required"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({ 'token': token.decode('UTF-8')})
    return make_response('Could n\'t verify', 401, {"WWW-Authenticate" : 'Basic realm="Login Required"'})

@app.route('/todo', methods=['GET'])
@token_check
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    result = todos_schema.dump(todos)
    
    return jsonify(result)


@app.route('/todo/<todo_id>', methods=['GET'])
@token_check
def get_single_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id ,user_id=current_user.id).first()
    
    if not todo:
        return jsonify({ 'msg' : 'no todo found'})
    
    return todo_schema.jsonify(todo)


@app.route('/todo', methods=['POST'])
@token_check
def create_todo(current_user):
    data = request.get_json()
    
    new_todo = Todo(body=data['body'], completed=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    
    return jsonify({ 'msg' : 'Todo created successfully' })


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_check
def update_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id ,user_id=current_user.id).first()
    
    if not todo:
        return jsonify({ 'msg' : 'no todo found'})
    
    data = request.get_json()
    
    todo.completed = data['completed']
    if data['body']:
        todo.body = data['body']
    
    db.session.commit()
    return jsonify({ 'msg' : 'Todo item has been updated!' })


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_check
def delete_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    
    if not todo:
        return jsonify({ 'msg' : 'no todo found'})
    
    db.session.delete(todo)
    db.session.commit()
    return jsonify({ "msg" : "Todo succcesfully deleted" })


if __name__ == '__main__':
    app.run(port=4000 ,debug=True)