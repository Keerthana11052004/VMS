import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv is not available, we'll use environment variables directly
    pass

class Config:
    # Load all configuration from environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'instance/uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # Database Configuration (loaded from .env)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'false').lower() in ['true', 'on', '1']
    
    # Enhanced SQLAlchemy Engine Options for Production MySQL Stability
    SQLALCHEMY_ENGINE_OPTIONS = {
        # Connection health check - verifies connections before use
        'pool_pre_ping': True,
        
        # Recycle connections after 1 hour to prevent MySQL timeout
        'pool_recycle': 3600,  # 1 hour in seconds
        
        # Timeout when getting connections from pool
        'pool_timeout': 30,
        
        # Size of connection pool
        'pool_size': 20,
        
        # Max overflow connections beyond pool_size
        'max_overflow': 30,
        
        # Additional MySQL-specific options for robustness
        'echo': False,  # Set to True only for debugging
        'pool_reset_on_return': 'commit',
        
        # MySQL-specific connection timeout settings
        'connect_args': {
            'connect_timeout': 10,
            'read_timeout': 30,
            'write_timeout': 30,
        }
    }
    
    # Connection Pool Settings
    SQLALCHEMY_POOL_RECYCLE = int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 120))
    SQLALCHEMY_POOL_TIMEOUT = int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', 10))
    SQLALCHEMY_POOL_PRE_PING = os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() in ['true', 'on', '1']
    
    # URL Scheme
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'https')
    
    # Session/Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ['true', 'on', '1']
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_SAMESITE = SESSION_COOKIE_SAMESITE
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PERMANENT_SESSION_LIFETIME', 60 * 60 * 8))
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.office365.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'sapnoreply@violintec.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'sapnoreply@violintec.com')
    
    # Feature Flags
    ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'true').lower() in ['true', 'on', '1']
    ENABLE_OTP = os.environ.get('ENABLE_OTP', 'true').lower() in ['true', 'on', '1']
    ENABLE_CAPTCHA = os.environ.get('ENABLE_CAPTCHA', 'true').lower() in ['true', 'on', '1']
    ENABLE_RATE_LIMITING = os.environ.get('ENABLE_RATE_LIMITING', 'true').lower() in ['true', 'on', '1']
    
    # URL Configuration
    URL_PREFIX = os.environ.get('URL_PREFIX', '/vms').rstrip('/')
