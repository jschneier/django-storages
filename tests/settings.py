import os

MEDIA_ROOT = os.path.join(os.path.normcase(os.path.dirname(os.path.abspath(__file__))), 'media')
MEDIA_URL = '/media/'

SITE_ID = 1

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'django.contrib.sites',
    'storages'
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)

DEFAULT_FILE_STORAGE = 'backends.s3boto.S3BotoStorage'
AWS_IS_GZIPPED = True
GS_IS_GZIPPED = True
SECRET_KEY = 'hailthesunshine'

# apache-libcloud settings
DEFAULT_LIBCLOUD_PROVIDER = 'libcloud_local'
LIBCLOUD_DIR = os.path.join(MEDIA_ROOT, 'libcloud')
LIBCLOUD_PROVIDERS = {
    'libcloud_local': {
        'type': 'libcloud.storage.types.Provider.LOCAL',
        'user': LIBCLOUD_DIR,
        'key': '',
        'bucket': 'local'
    },
}