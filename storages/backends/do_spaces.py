from django.conf import settings
from .s3boto3 import S3Boto3Storage


class DigitalOceanSpacesStorage(S3Boto3Storage):
    access_key = settings.DO_SPACES_ACCESS_KEY_ID
    secret_key = settings.DO_SPACES_SECRET_ACCESS_KEY
    location = settings.DO_SPACES_SPACE_FOLDER
    bucket_name = settings.DO_SPACES_SPACE_NAME
    endpoint_url = settings.DO_SPACES_ENDPOINT_URL
    default_acl = settings.DO_SPACES_DEFAULT_ACL

    object_parameters = {
        'CacheControl': 'max-age={CACHE_MAX_AGE}'.format(
            CACHE_MAX_AGE=settings.DO_SPACES_CACHE_MAX_AGE
        )
    }
    signature_version = 's3'


class DigitalOceanSpacesStaticStorage(DigitalOceanSpacesStorage):
    location = settings.DO_SPACES_STATIC_LOCATION


class DigitalOceanSpacesPublicMediaStorage(DigitalOceanSpacesStorage):
    location = settings.DO_SPACES_PUBLIC_MEDIA_LOCATION
    file_overwrite = False


class DigitalOceanSpacesPrivateMediaStorage(DigitalOceanSpacesStorage):
    location = settings.DO_SPACES_PRIVATE_MEDIA_LOCATION
    default_acl = 'private'
    file_overwrite = False
    custom_domain = False
