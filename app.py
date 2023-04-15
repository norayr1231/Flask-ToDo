#Lesson 2 24/03/2023

from datetime import timedelta
import datetime
from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(200), nullable = False)
    password = db.Column(db.String(200), nullable = False)

class Task(db.Model):
    user = db.Colum




@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        if password == repeat_password:
            password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = {
                'name': name,
                'email': email,
                'password': password
            }
            users.append(new_user)
            print(users)
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
                    token_expiry = datetime.utcnow() + timedelta(minutes=200) # set token expiration time to 1 minute from now
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