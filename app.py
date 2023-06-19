import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        return self.password_hash
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    
    def __repr__(self):
        return '<User %r>' % self.username
    
    
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        hashed_password = generate_password_hash(request.form.get('password_hash'), method='sha256')
        print(hashed_password)
        data = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(data)
        db.session.commit()
        flash('User successfully registered')
        return render_template('dashboard.html')
    else:
        return render_template('index.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user:
            if check_password_hash(user.password_hash, request.form.get('password_hash')):
                flash('Logged in successfully')
                return render_template('dashboard.html')
            else:
                flash('Invalid username or password')
                return render_template('login.html')
            
        else:
            flash('User does not exist')
            return render_template('login.html')
    else:
        return render_template('login.html')
    
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == "POST":
        user = User.query.filter_by(username= request.form.get('username')).first()
        if user:
            if request.form.get('password_hash') == request.form.get('password_hash2'):
                user.password_hash = generate_password_hash(request.form.get('password_hash'), method='sha256')
                db.session.commit()
                flash('Password successfully changed, please login with your new password')
                return render_template('login.html')
            
            else:
                flash('Password does not match')
                return render_template('forgot_password.html')
            
        else:
            flash('Invalid username')
            return render_template('forgot_password.html')
    else:
        flash('Invalid username')
        return render_template('forgot_password.html')
    
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
        
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500












if __name__ == '__main__':
    app.run(debug=True)