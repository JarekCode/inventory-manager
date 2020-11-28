from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flaskApi import secretsFile

app = Flask(__name__)
app.config['SECRET_KEY'] = secretsFile.getItem('appConfigSecretKey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///credentials.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
# Used for @login_required decorator for routes
login_manager.login_view = 'login'
# Create a nice message for @login_required
login_manager.login_message_category = 'info'

from flaskApi import routes