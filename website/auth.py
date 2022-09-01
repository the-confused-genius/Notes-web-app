from hashlib import sha256
import imp
from unicodedata import category
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash('Logged in successfully', category='success')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('The password is incorrect, try again',category='error')
        else:
            flash('Email does not exist',category='error')

    return render_template('login.html',user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exist',category='error')
        elif len(email) < 4:
            flash('Email must be greated than 4 characters',category='error')
        elif firstName==None or len(firstName) < 4:
            flash('Name must be greated than 4 characters',category='error')
        elif password1 != password2:
            flash('The passwords don\'t match',category='error')
        elif password1==None or len(password1)  < 7:
            flash('The password must be at least 7 characters',category='error')
        else:
            new_user = User(email=email,first_name=firstName,password=generate_password_hash(password1,method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
            login_user(user,remember=True)
            flash('Account created',category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html',user=current_user)