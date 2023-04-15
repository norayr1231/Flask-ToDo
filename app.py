
from datetime import timedelta
import datetime
import os
from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, Column
import bcrypt
import jwt
from flask_login import LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,EqualTo

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
           'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'SECRET_KEY'


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model):
    id = Column(db.Integer, primary_key=True)
    username = Column(db.String(200), nullable = False)
    password = Column(db.String(200), nullable = False)
    tasks = db.relationship('Task', backref='user')

class Task(db.Model):
    id = Column(db.Integer, primary_key=True)
    titile = Column(db.String(60), nullable=True)
    description = Column(db.Text)
    date = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(db.Integer, db.ForeignKey('user.id'))


class RegistrationForm(FlaskForm):
    username = StringField('username', validators =[DataRequired()])
    email = StringField('Email', validators=[DataRequired(),Email()])
    password1 = PasswordField('Password', validators = [DataRequired()])
    password2 = PasswordField('Confirm Password', validators = [DataRequired(),EqualTo('password1')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me',validators= [DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['name']
        password = request.form['password']
        print(username+"none/n")
        repeat_password = request.form['repeat_password']
        if password == repeat_password:
            password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        return "Password did not match"
    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        for user in users:
            print("USER ", user)
            if user['email'] == email:
                password = password.encode('utf-8')
                if bcrypt.checkpw(password, user['password']):
                    token_expiry = datetime.utcnow() + timedelta(minutes=200)
                    token = jwt.encode({'email': email, 'exp': token_expiry}, app.config['SECRET_KEY'], algorithm='HS256')
                    resp = make_response(redirect(url_for('dashboard')))
                    resp.set_cookie('token', token)
                    return resp
    return render_template('login.html')

@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    token = request.cookies.get('token')
    print(token)
    if not token:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        # check if token is expired
        if datetime.utcnow() > datetime.fromtimestamp(data['exp']):
            return redirect(url_for('login'))
    except jwt.exceptions.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.InvalidTokenError:
        return redirect(url_for('login'))

    # Only allow access to the dashboard for authenticated users
    return render_template('dashboard.html')

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)
