import os
ROOT_PATH = os.path.dirname(__file__)

TEMPLATE_DEBUG = DEBUG = True
MANAGERS = ADMINS = ()
DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = os.path.join(ROOT_PATH, 'testdb.sqlite')

TIME_ZONE = 'America/Chicago'
LANGUAGE_CODE = 'en-us'
SITE_ID = 1
USE_I18N = True
MEDIA_ROOT = ''
MEDIA_URL = ''
ADMIN_MEDIA_PREFIX = '/media/'
SECRET_KEY = '2+@4vnr#v8e273^+a)g$8%dre^dwcn#d&n#8+l6jk7r#$p&3zk'
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
)
MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)
ROOT_URLCONF = 'urls'
TEMPLATE_DIRS = (os.path.join(ROOT_PATH, 'templates'),)
INSTALLED_APPS = (
    's3project', # ugly but easier
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
)

DEFAULT_FILE_STORAGE = 'backends.S3Storage.S3Storage'

from S3 import CallingFormat
AWS_CALLING_FORMAT = CallingFormat.SUBDOMAIN
AWS_HEADERS = {
    'Expires': 'Thu, 15 Apr 2010 20:00:00 GMT', # see http://developer.yahoo.com/performance/rules.html#expires
    'Cache-Control': 'max-age=86400',
    }

# local_settings.py can be used to override environment-specific settings
# like database and email that differ between development and production.
# Add you custom AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and 
# AWS_STORAGE_BUCKET_NAME settings
try:
    from local_settings import *
except ImportError:
    pass
