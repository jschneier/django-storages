from django.conf import settings
from storages.backends.s3boto import S3BotoStorage

from boto.gs.connection import GSConnection, SubdomainCallingFormat
from boto.exception import GSResponseError

ACCESS_KEY_NAME = getattr(settings, 'GS_ACCESS_KEY_ID', None)
SECRET_KEY_NAME = getattr(settings, 'GS_SECRET_ACCESS_KEY', None)
HEADERS = getattr(settings, 'GS_HEADERS', {})
STORAGE_BUCKET_NAME = getattr(settings, 'GS_BUCKET_NAME', None)
AUTO_CREATE_BUCKET = getattr(settings, 'GS_AUTO_CREATE_BUCKET', False)
DEFAULT_ACL = getattr(settings, 'GS_DEFAULT_ACL', 'public-read')
BUCKET_ACL = getattr(settings, 'GS_BUCKET_ACL', DEFAULT_ACL)
QUERYSTRING_AUTH = getattr(settings, 'GS_QUERYSTRING_AUTH', True)
QUERYSTRING_EXPIRE = getattr(settings, 'GS_QUERYSTRING_EXPIRE', 3600)
REDUCED_REDUNDANCY = getattr(settings, 'GS_REDUCED_REDUNDANCY', False)
LOCATION = getattr(settings, 'GS_LOCATION', '')
CUSTOM_DOMAIN = getattr(settings, 'GS_CUSTOM_DOMAIN', None)
CALLING_FORMAT = getattr(settings, 'GS_CALLING_FORMAT', SubdomainCallingFormat())
SECURE_URLS = getattr(settings, 'GS_SECURE_URLS', True)
FILE_NAME_CHARSET = getattr(settings, 'GS_FILE_NAME_CHARSET', 'utf-8')
FILE_OVERWRITE = getattr(settings, 'GS_FILE_OVERWRITE', True)
FILE_BUFFER_SIZE = getattr(settings, 'GS_FILE_BUFFER_SIZE', 5242880)
IS_GZIPPED = getattr(settings, 'GS_IS_GZIPPED', False)
PRELOAD_METADATA = getattr(settings, 'GS_PRELOAD_METADATA', False)
GZIP_CONTENT_TYPES = getattr(settings, 'GS_GZIP_CONTENT_TYPES', (
    'text/css',
    'application/javascript',
    'application/x-javascript',
))


class GSBotoStorage(S3BotoStorage):
    connection_class = GSConnection
    connection_response_error = GSResponseError

    def __init__(self, bucket=STORAGE_BUCKET_NAME, access_key=None,
            secret_key=None, bucket_acl=BUCKET_ACL, acl=DEFAULT_ACL,
            headers=HEADERS, gzip=IS_GZIPPED,
            gzip_content_types=GZIP_CONTENT_TYPES,
            querystring_auth=QUERYSTRING_AUTH,
            querystring_expire=QUERYSTRING_EXPIRE,
            reduced_redundancy=REDUCED_REDUNDANCY,
            custom_domain=CUSTOM_DOMAIN, secure_urls=SECURE_URLS,
            location=LOCATION, file_name_charset=FILE_NAME_CHARSET,
            preload_metadata=PRELOAD_METADATA,
            calling_format=CALLING_FORMAT):
        super(GSBotoStorage, self).__init__(bucket=bucket,
            access_key=access_key, secret_key=secret_key,
            bucket_acl=bucket_acl, acl=acl, headers=headers, gzip=gzip,
            gzip_content_types=gzip_content_types,
            querystring_auth=querystring_auth,
            querystring_expire=querystring_expire,
            reduced_redundancy=reduced_redundancy,
            custom_domain=custom_domain, secure_urls=secure_urls,
            location=location, file_name_charset=file_name_charset,
            preload_metadata=preload_metadata, calling_format=calling_format)
