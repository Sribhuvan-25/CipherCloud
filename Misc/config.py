import os

class Config:
    """Base configuration."""
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'files')
    DATABASE_PATH = os.path.join(BASE_DIR, 'storage', 'secure_storage.db')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False

class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    DATABASE_PATH = ':memory:'  # Use in-memory database for testing
    UPLOAD_FOLDER = os.path.join(Config.BASE_DIR, 'tests', 'test_files')

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False 