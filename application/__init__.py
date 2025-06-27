# application/__init__.py

from flask import Flask
from flask_mongoengine import MongoEngine
from flask_mail import Mail
from flask_login import LoginManager
from config import Config
from bson import ObjectId  # Import ObjectId from bson

# Initialize the app and all extensions
app = Flask(__name__)
app.config.from_object(Config)

# Initialize the database (MongoEngine)
db = MongoEngine()
db.init_app(app)

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # The endpoint for the login page (set to 'login')

@login_manager.user_loader
def load_user(user_id):
    from application.models import User  # Import here to avoid circular imports
    # Use ObjectId instead of converting user_id to an integer
    return User.objects(id=ObjectId(user_id)).first()

# Import routes here after all initializations to avoid circular imports
from application import routes
