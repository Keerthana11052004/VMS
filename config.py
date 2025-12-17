import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv is not available, we'll use environment variables directly
    pass

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    # Store uploads outside static web root
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'instance/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLAlchemy Connection Pool Settings for MySQL
    SQLALCHEMY_POOL_RECYCLE = 120  # Recycle connections after 2 minutes
    SQLALCHEMY_POOL_TIMEOUT = 10   # Timeout for getting a connection from the pool
    SQLALCHEMY_POOL_PRE_PING = True # Test connection before using it
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'https')

    # Session / Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    # Default to False for local/dev; set to true via env in prod
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ['true', 'on', '1']
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_SAMESITE = SESSION_COOKIE_SAMESITE
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PERMANENT_SESSION_LIFETIME', 60 * 60 * 8))  # 8h

    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.office365.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'sapnoreply@violintec.com')
    # Do not hardcode passwords; use environment variables
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'sapnoreply@violintec.com')
    
    # Database Configuration
    DB_TYPE = os.environ.get('DB_TYPE', 'mysql') # default mysql if provided via env
    
    if DB_TYPE == 'mysql':
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    elif DB_TYPE == 'postgresql':
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    else:
        # Default to SQLite
        SQLALCHEMY_DATABASE_URI = 'sqlite:///vms.db'

    # Feature Flags
    ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'true').lower() in ['true', 'on', '1']
    ENABLE_OTP = os.environ.get('ENABLE_OTP', 'true').lower() in ['true', 'on', '1']
    ENABLE_CAPTCHA = os.environ.get('ENABLE_CAPTCHA', 'true').lower() in ['true', 'on', '1']
