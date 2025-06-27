# application/models.py

from application import db
from flask_login import UserMixin  # Import UserMixin for easy integration
from mongoengine import Document, StringField, IntField, DateTimeField, ListField, DictField
from datetime import datetime

class User(db.Document, UserMixin):  # Inherit from UserMixin for Flask-Login
    user_id = db.IntField(unique=True)  # Custom user_id
    first_name = db.StringField(max_length=50)
    last_name = db.StringField(max_length=50)
    phone = db.StringField()
    email = db.StringField(max_length=30, unique=True)
    password = db.StringField()
    otp = db.StringField(nullable=True)

class Vulnerabilities(Document):  
    ip = StringField(required=True, unique=True)  # IPs are strings, not ints
    hostname = StringField(max_length=50)
    os = StringField(max_length=50)
    ports = ListField(IntField())  # A list of integers (e.g., [22, 80])
    port_details = ListField(DictField())  # List of port info dicts
    firewall_detected = StringField()
    ssh_failed = StringField()
    risk = StringField()
    scanned_at = DateTimeField(default=datetime.utcnow)

class Attackers(Document):  
    ip = StringField(required=True, unique=True)  # e.g., "192.168.1.15"
    failures = IntField(required=True)  # store as integer, not string
    detected_at = DateTimeField(default=datetime.utcnow)  # proper datetime field


    def get_id(self):
        # Flask-Login expects the user identifier to be a string
        return str(self.id)  # Use the default _id field from MongoDB
