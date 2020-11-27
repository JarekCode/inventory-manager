from flask import render_template
from flaskApi import app

# Home
@app.route('/')
def home():
  return render_template('home.html', page_title = 'Home')