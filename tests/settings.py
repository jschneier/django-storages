MEDIA_URL = '/media/'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }
}

SECRET_KEY = 'hailthesunshine'

USE_TZ = True

# the following test settings are required for moto to work.
AWS_STORAGE_BUCKET_NAME = "test_bucket"
AWS_ACCESS_KEY_ID = "testing_key_id"
AWS_SECRET_ACCESS_KEY = "testing_access_key"
