
from datetime import datetime
import datetime
import os
from flask import Flask, flash, jsonify, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, Column
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Email,EqualTo

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
           'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


class User(UserMixin, db.Model):
    id = Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique = True, index = True)
    username = Column(db.String(200), nullable = False)
    password_hash = Column(db.String(200), nullable = False)
    tasks = db.relationship('Task', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
      return check_password_hash(self.password_hash,password)


class Task(db.Model):
    id = Column(db.Integer, primary_key=True)
    title = Column(db.String(60), nullable=True)
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
    submit = SubmitField('Login')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods = ['POST','GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username =form.username.data, email = form.email.data)
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            return redirect(next or url_for('dashboard'))
        flash('Invalid email address or Password.')    
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    user_id = current_user.get_id()
    task_list = Task.query.filter_by(user_id=user_id)
    if request.method == 'POST':
        task = Task(title = request.form['title'], description = request.form['description'], user_id=user_id)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', task_list=task_list)


@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)
