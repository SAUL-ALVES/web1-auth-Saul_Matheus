import os
from dotenv import load_dotenv


load_dotenv()


LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')


JWT_SECRET = os.getenv('JWT_SECRET', 'default-secret-key')

JWT_EXPIRES_MIN = int(os.getenv('JWT_EXPIRES_MIN', '15'))


FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default-flask-secret-key')