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

#------#
# Home #
#------#

# Home
@app.route('/')
def home():
  if(current_user.is_authenticated):
    # Return studentHome
    if(current_user.role == 'admin'):
      return redirect(url_for('adminHome'))
    # Return instructor
    # elif(current_user.role == 'employee'):
    #   return redirect(url_for('employeeHome'))
    # Return Access Pending if a new user was not yet approved by an admin
    elif(current_user.role == 'pending'):
      return render_template('accessPending.html', page_title = 'Access Pending')
    elif(current_user.role == 'deactivated'):
      return render_template('accessDeactivated.html', page_title = 'Account Deactivated')
    
  else:
    # Return unauthenticated
    return render_template('home.html', page_title = 'Home')

# Admin Home
@app.route('/admin')
@login_required
def adminHome():
  # Check if the person logged in is an admin
  if(current_user.role != 'admin'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Return adminHome
  return render_template('admin_home.html', page_title = 'Home')

# Admin Profile
@app.route('/admin/profile')
@login_required
def adminProfile():
  # Check if the person logged in is an admin
  if(current_user.role != 'admin'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  image_file = url_for('static', filename='profile_pictures/' + current_user.image_file)
  # Return adminProfile
  return render_template('admin_profile.html', page_title = 'My Profile', image_file = image_file)

# Manage accounts
@app.route('/admin/accounts')
@login_required
def adminAccounts():
  # Check if the person logged in is an admin
  if(current_user.role != 'admin'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Get all people in the application (1. admins, 2. employees, 3. pending, 4. deactivated)
  allAdmins = User.query.filter_by(role='admin').all()
  allEmployees = User.query.filter_by(role='employee').all()
  allPending = User.query.filter_by(role='pending').all()
  allDeactivated = User.query.filter_by(role='deactivated').all()

  # Replace the hashed passwords with 'N/A' and replace image_file with img link
  for i in allAdmins:
    i.password = i.password.replace(i.password, 'N/A')
    i_m = url_for('static', filename='profile_pictures/' + i.image_file)
    i.image_file = i_m
  for i in allEmployees:
    i.password = i.password.replace(i.password, 'N/A')
    i_m = url_for('static', filename='profile_pictures/' + i.image_file)
    i.image_file = i_m
  for i in allPending:
    i.password = i.password.replace(i.password, 'N/A')
    i_m = url_for('static', filename='profile_pictures/' + i.image_file)
    i.image_file = i_m
  for i in allDeactivated:
    i.password = i.password.replace(i.password, 'N/A')
    i_m = url_for('static', filename='profile_pictures/' + i.image_file)
    i.image_file = i_m

  # Return
  return render_template('admin_accounts.html', allAdmins = allAdmins, allEmployees = allEmployees, allPending = allPending, allDeactivated = allDeactivated, page_title = 'Accounts')

# Change role of an account
@app.route('/admin/accounts/<email_address>/changeRole/<new_role>')
@login_required
def adminAccountsChangeRole(email_address, new_role):
  # Check if the person logged in is an admin
  if(current_user.role != 'admin'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Check if the user email exists in db
  user = User.query.filter_by(email=email_address).first()
  if(user is None):
    flash(f'"{email_address}" does not exist in the database', 'danger')
    return redirect(url_for('adminAccounts'))
  # Check if the role is ['admin' or 'employee' or 'deactivated']
  validRoles = ['admin', 'employee', 'deactivated']
  if(new_role not in validRoles):
    flash(f'"{new_role}" is not valid. Valid Roles: "admin", "employee", "deactivated".', 'danger')
    return redirect(url_for('adminAccounts'))
  # Update user role
  user.role = new_role
  db.session.add(user)
  db.session.commit()
  # Return redirect
  flash(f'"{email_address}" role updated to "{new_role}"', 'success')
  return redirect(url_for('adminAccounts'))

# Delete user from the database
@app.route('/admin/accounts/<email_address>/deleteUser')
@login_required
def adminAccountsDeleteUser(email_address):
  # Check if the person logged in is an admin
  if(current_user.role != 'admin'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Check if the user email exists in db
  user = User.query.filter_by(email=email_address).first()
  if(user is None):
    flash(f'"{email_address}" does not exist in the database.', 'danger')
    return redirect(url_for('adminAccounts'))
  # Delete user
  userToDelete = User.query.filter_by(email=email_address).first()
  db.session.delete(userToDelete)
  db.session.commit()
  # Return redirect
  flash(f'"{email_address}" user has been deleted.', 'success')
  return redirect(url_for('adminAccounts'))
'''
admin
- view pending users
- approve pending users
- deny pending users

- view all users
- deactivate users
- re-activate users
- delete users

- view inventory
- view logs
- view transactions

employee
- view inventory
- add items
- remove items
- update items
- view my transactions
'''