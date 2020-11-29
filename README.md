# Inventory Manager

## Setup
    virtualenv venv
    source venv/bin/activate
    pip install -r requirements.txt

### SQLite - Create Database
    from flaskApi import db
    from flaskApi.models import *
    db.create_all()

### SQLite - Query Database
    from flaskApi import db
    from flaskApi.models import *
    User.query.all()

### Run The Application
    python3 flaskApi.py