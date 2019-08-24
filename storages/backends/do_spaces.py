
from django.conf import settings

from .s3boto3 import S3Boto3Storage
from storages.utils import (
    check_location, get_available_overwrite_name, lookup_env, safe_join,
    setting,
)


class DigitalOceanSpacesStorage(S3Boto3Storage):
    access_key = setting('DO_SPACES_ACCESS_KEY_ID')
    secret_key = setting('DO_SPACES_SECRET_ACCESS_KEY')
    location = setting('DO_SPACES_SPACE_FOLDER','')
    bucket_name = setting('DO_SPACES_SPACE_NAME')
    endpoint_url = setting('DO_SPACES_ENDPOINT_URL')
    default_acl = setting('DO_SPACES_DEFAULT_ACL','public-read')

    object_parameters = {
        'CacheControl': 'max-age={CACHE_MAX_AGE}'.format(
            CACHE_MAX_AGE=setting('DO_SPACES_CACHE_MAX_AGE',86400)
        )
    }
    signature_version = 's3'


class DigitalOceanSpacesStaticStorage(DigitalOceanSpacesStorage):
    location = setting('DO_SPACES_STATIC_LOCATION')
    default_acl = 'public-read'


class DigitalOceanSpacesPublicMediaStorage(DigitalOceanSpacesStorage):
    location = setting('DO_SPACES_PUBLIC_MEDIA_LOCATION')
    file_overwrite = False
    default_acl = 'public-read'


class DigitalOceanSpacesPrivateMediaStorage(DigitalOceanSpacesStorage):
    location = setting('DO_SPACES_PRIVATE_MEDIA_LOCATION')
    default_acl = 'private'
    file_overwrite = False
    custom_domain = False
