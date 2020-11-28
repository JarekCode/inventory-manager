from flaskApi.models import User
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, DecimalField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

class RegisterForm(FlaskForm):
  # -----------
  # Form fields
  # -----------
  first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)], render_kw={"placeholder": "First Name"})
  last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)], render_kw={"placeholder": "Last Name"})
  email = StringField('Email', validators=[DataRequired(), Email(), Length(min=2, max=64)], render_kw={"placeholder": "Email"})
  password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=64)], render_kw={"placeholder": "Password"})
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Repeat Password"})
  form_submit = SubmitField('Create Account')
  # ---------------------
  # Additional Validation
  # ---------------------
  # Email: Validate if an account with email passed in is already in the SQLite database
  def validate_email(self, email):
    user = User.query.filter_by(email = email.data.lower()).first()
    if(user):
      raise ValidationError('This email address is taken. Please log in or reset password.')

class LoginForm(FlaskForm):
  # -----------
  # Form fields
  # -----------
  email = StringField('Email', validators=[DataRequired(), Email(), Length(min=2, max=64)], render_kw={"placeholder": "Email"})
  password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=64)], render_kw={"placeholder": "Password"})
  remember = BooleanField('Remember Me')
  form_submit = SubmitField('Login')

class RequestPasswordResetForm(FlaskForm):
  # -----------
  # Form fields
  # -----------
  email = StringField('Email', validators=[DataRequired(), Email(), Length(min=2, max=64)], render_kw={"placeholder": "Email"})
  form_submit = SubmitField('Request Password Reset')
  # ---------------------
  # Additional Validation
  # ---------------------
  # Email: Validate if an account exists in the database with the email passed in.
  def validate_email(self, email):
    user = User.query.filter_by(email = email.data.lower()).first()
    if(user is None):
      raise ValidationError('There is no account with this email. You must register first.')

class ResetPasswordForm(FlaskForm):
  # -----------
  # Form fields
  # -----------
  password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=64)], render_kw={"placeholder": "New Password"})
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Repeat Password"})
  form_submit = SubmitField('Reset Password')