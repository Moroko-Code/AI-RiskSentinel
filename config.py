import os
import pymongo

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or b'6\xe9\xda\xead\x81\xf7\x8d\xbbH\x87\xe8m\xdd3%'
    MONGODB_SETTINGS = { 'db' : 'RISK' }
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'mathewmoroko@gmail.com'
    MAIL_PASSWORD = 'fvmx ekfj owug wabo'
    MAIL_DEFAULT_SENDER = 'mathewmoroko@gmail.com'

     # Create MongoClient
    client = pymongo.MongoClient("mongodb://localhost:27017/")  # Update if necessary
    db = client['RISK']
    vulnerabilities_collection = db['vulnerabilities']


