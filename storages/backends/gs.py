try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO  # noqa

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

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            provider = self.key.bucket.connection.provider
            upload_headers = {provider.acl_header: self._storage.default_acl}
            upload_headers.update(self._storage.headers)
            self._storage._save_content(self.key, self.file, upload_headers)
        self.key.close()


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
