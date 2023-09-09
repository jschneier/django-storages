MEDIA_URL = "/media/"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

SECRET_KEY = "hailthesunshine"

USE_TZ = True

# the following test settings are required for moto to work.
AWS_STORAGE_BUCKET_NAME = "test-bucket"
