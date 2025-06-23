MEDIA_URL = "/media/"
# Test settings for django-storages

DEBUG = True
USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sites",
    "storages",
]

SITE_ID = 1
MIDDLEWARE_CLASSES = ()
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Storage-specific settings for tests
LIBCLOUD_PROVIDERS = {
    'default': {
        'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    's3': {
        'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'azure': {
        'type': 'libcloud.storage.types.Provider.AZURE_BLOBS',
        'user': 'testuser',
        'key': 'test',
        'bucket': 'test-bucket',
    },
}
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

SECRET_KEY = "hailthesunshine"
"""Django settings for tests."""

SECRET_KEY = "django-storages-tests-secret-key"

DEBUG = True

USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sites",
    "storages",
]

SITE_ID = 1

MIDDLEWARE_CLASSES = ()

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Storage-specific settings for tests
LIBCLOUD_PROVIDERS = {
    'default': {
        'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    's3': {
        'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'google': {
        'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'azure': {
        'type': 'libcloud.storage.types.Provider.AZURE_BLOBS',
        'user': 'testuser',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'backblaze': {
        'type': 'libcloud.storage.types.Provider.BACKBLAZE_S3',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'unknown': {
        'type': 'libcloud.storage.types.Provider.UNKNOWN',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
}
USE_TZ = True

# the following test settings are required for moto to work.
AWS_STORAGE_BUCKET_NAME = "test-bucket"
