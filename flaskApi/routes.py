#!/bin/env/python
from flask import render_template, request, url_for, flash, redirect, session
from flaskApi import app, db, bcrypt, secretsFile
from flaskApi.forms import RegisterForm, LoginForm, RequestPasswordResetForm, ResetPasswordForm
from flaskApi.templates import *
from flaskApi.models import User
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, date, timedelta
import smtplib

#--------#
# Errors #
#--------#

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html', page_title = 'Page Not Found'), 404

@app.errorhandler(500)
def internal_error(e):
    # note that we set the 500 status explicitly
    return render_template('500.html', page_title = 'Internal Error'), 500

#---------------------------#
# Register / Login / Logout #
#---------------------------#

# Register
@app.route('/register', methods = ['GET', 'POST'])
def register():
  # Check if user is already logged in. Exit if they are
  if(current_user.is_authenticated):
    return redirect(url_for('home'))
  # Register Form
  form = RegisterForm()
  # ----
  # POST
  # ----
  # Form submit
  if(form.validate_on_submit()):
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    # Store the new user to DB
    user = User(first_name = form.first_name.data, last_name = form.last_name.data, email = form.email.data.lower(), password = hashed_password)
    db.session.add(user)
    db.session.commit()
    # Flash Message: Account created
    flash('Your account has been successfully created!', 'success')
    # Return
    return redirect(url_for('login'))
  # ---
  # GET
  # ---
  # Return
  return render_template('signin_register.html', page_title = 'Register', form = form)

# Login
@app.route('/login', methods = ['GET', 'POST'])
def login():
  # Check if user is already logged in. Exit if they are
  if(current_user.is_authenticated):
    return redirect(url_for('home'))
  # Login Form
  form = LoginForm()
  # ----
  # POST
  # ----
  # Form submit
  if(form.validate_on_submit()):
    # Make sure the user exists in the database. Will return None if not
    user = User.query.filter_by(email = form.email.data.lower()).first()
    # Check if the user exists from above query and compare if passwords match
    if(user and bcrypt.check_password_hash(user.password, form.password.data)):
      # Login using the flask_login extention
      login_user(user, remember = form.remember.data)
      # Using 'get' returns None if it does not exist
      next_page = request.args.get('next')
      # Return redirect to arg in url if it exists, not the default home page
      if(next_page):
        return redirect(next_page)
      else:
        return redirect(url_for('home'))
    else:
      # Flash Message: Login unsuccessful
      flash(f'Login Failed. Please check your Email and Password.', 'danger')
  # ---
  # GET
  # ---
  # Return
  return render_template('signin_login.html', page_title = 'Login', form = form)

# Logout
@app.route('/logout')
def logout():
  # Logout the user
  logout_user()
  # Return redirect
  return redirect(url_for('home'))

#----------------#
# Password Reset #
#----------------#

# Send email with password reset token
def send_password_reset_email(user):
  # --- Delete from Here ---
  # Temporary because email is not set up
  token = user.get_reset_password_token()
  print("Password Reset Token:", token)
  return
  # End of temporary print
  # --- Delete to here ---
  s = smtplib.SMTP()
  s.connect(secretsFile.getItem('mailServer'), secretsFile.getItem('mailPort'))
  s.starttls()
  s.login(secretsFile.getItem('mailUsername'), secretsFile.getItem('mailPassword'))
  token = user.get_reset_password_token()
  msg = f'From: {secretsFile.getItem("mailEmail")}\nTo: {user.email}\nSubject: Password Reset Request\n\nTo reset your password, visit the following link:\n\n{url_for("reset_token", token = token, _external = True)}\n\nIf you did not make this request, simply ignore this email and no changes will be made.'
  s.sendmail(secretsFile.getItem('mailEmail'), user.email, msg)

# User requests to reset a password providing a new email address
@app.route('/reset_password', methods = ['GET', 'POST'])
def reset_request():
  # Check if user is already logged in,
  # User should be logged out before resetting password.
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))
  # Request Password Reset Form
  form = RequestPasswordResetForm()
  # ----
  # POST
  # ----
  if(form.validate_on_submit()):
    # Get the user from database using the email from the form
    user = User.query.filter_by(email=form.email.data).first()
    # Send this user an email with the token to reset the password
    send_password_reset_email(user)
    # Flash Message: email sent
    flash('An email has been sent with instructions on how to reset your password!', 'info')
    # Return redirect
    return redirect(url_for('login'))
  # ---
  # GET
  # ---
  # Return
  return render_template('signin_reset_password_request.html', page_title = 'Reset Password', form = form)

# Using a valid token, user sets a new password
@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_token(token):
  # Check if user is already logged in,
  # User should be logged out before resetting password.
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))
  # Verify the token from the email, None if token not valid/expired
  # User payload from the database is received if the token is valid
  user = User.verify_password_reset_token(token)
  if(user is None):
    flash('The token is invalid/expired.', 'warning')
    return redirect(url_for('reset_request'))
  # From here on, the token is valid, so create the password reset form
  form = ResetPasswordForm()
  # ----
  # POST
  # ----
  if(form.validate_on_submit()):
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    # Setting the new hashed password for the user
    user.password = hashed_password
    db.session.commit()
    # Flash Message: account created
    flash('Your password has been updated!', 'success')
    # Return redirect
    return redirect(url_for('login'))
  # ---
  # GET
  # ---
  # Return
  return render_template('signin_reset_password.html', page_title = 'Reset Password', form = form)

# Home
@app.route('/')
def home():
  return render_template('home.html', page_title = 'Home')