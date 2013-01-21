from django.core.exceptions import ImproperlyConfigured

from storages.backends.s3boto import S3BotoStorage, S3BotoStorageFile, setting

try:
    from boto.gs.connection import GSConnection, SubdomainCallingFormat
    from boto.exception import GSResponseError
    from boto.gs.key import Key as GSKey
except ImportError:
    raise ImproperlyConfigured("Could not load Boto's Google Storage bindings.\n"
                               "See https://github.com/boto/boto")


class GSBotoStorageFile(S3BotoStorageFile):
    buffer_size = setting('GS_FILE_BUFFER_SIZE', 5242880)


class GSBotoStorage(S3BotoStorage):
    connection_class = GSConnection
    connection_response_error = GSResponseError
    file_class = GSBotoStorageFile
    key_class = GSKey

    access_key = setting('GS_ACCESS_KEY_ID')
    secret_key = setting('GS_SECRET_ACCESS_KEY')
    file_overwrite = setting('GS_FILE_OVERWRITE', True)
    headers = setting('GS_HEADERS', {})
    storage_bucket_name = setting('GS_BUCKET_NAME', None)
    auto_create_bucket = setting('GS_AUTO_CREATE_BUCKET', False)
    default_acl = setting('GS_DEFAULT_ACL', 'public-read')
    bucket_acl = setting('GS_BUCKET_ACL', default_acl)
    querystring_auth = setting('GS_QUERYSTRING_AUTH', True)
    querystring_expire = setting('GS_QUERYSTRING_EXPIRE', 3600)
    reduced_redundancy = setting('GS_REDUCED_REDUNDANCY', False)
    location = setting('GS_LOCATION', '')
    custom_domain = setting('GS_CUSTOM_DOMAIN')
    calling_format = setting('GS_CALLING_FORMAT', SubdomainCallingFormat())
    secure_urls = setting('GS_SECURE_URLS', True)
    file_name_charset = setting('GS_FILE_NAME_CHARSET', 'utf-8')
    is_gzipped = setting('GS_IS_GZIPPED', False)
    preload_metadata = setting('GS_PRELOAD_METADATA', False)
    gzip_content_types = setting('GS_GZIP_CONTENT_TYPES', (
        'text/css',
        'application/javascript',
        'application/x-javascript',
    ))
    url_protocol = setting('GS_URL_PROTOCOL', 'http:')
