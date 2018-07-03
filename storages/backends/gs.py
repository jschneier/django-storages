import warnings

from django.core.exceptions import ImproperlyConfigured
from django.utils.deconstruct import deconstructible
from django.utils.six import BytesIO

from storages.backends.s3boto import S3BotoStorage, S3BotoStorageFile
from storages.utils import setting

try:
    from boto.gs.connection import GSConnection, SubdomainCallingFormat
    from boto.exception import GSResponseError
    from boto.gs.key import Key as GSKey
except ImportError:
    raise ImproperlyConfigured("Could not load Boto's Google Storage bindings.\n"
                               "See https://github.com/boto/boto")


warnings.warn("DEPRECATION NOTICE: This backend is deprecated in favour of the "
              "\"gcloud\" backend.  This backend uses Google Cloud Storage's XML "
              "Interoperable API which uses keyed-hash message authentication code "
              "(a.k.a. developer keys) that are linked to your Google account.  The "
              "interoperable API is really meant for migration to Google Cloud "
              "Storage.  The biggest problem with the developer keys is security and "
              "privacy.  Developer keys should not be shared with anyone as they can "
              "be used to gain access to other Google Cloud Storage buckets linked "
              "to your Google account.", DeprecationWarning)


class GSBotoStorageFile(S3BotoStorageFile):

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self.file = BytesIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            provider = self.key.bucket.connection.provider
            upload_headers = {provider.acl_header: self._storage.default_acl}
            upload_headers.update(self._storage.headers)
            self._storage._save_content(self.key, self.file, upload_headers)
        self.key.close()


@deconstructible
class GSBotoStorage(S3BotoStorage):
    connection_class = GSConnection
    connection_response_error = GSResponseError
    file_class = GSBotoStorageFile
    key_class = GSKey

    access_key_names = ['GS_ACCESS_KEY_ID']
    secret_key_names = ['GS_SECRET_ACCESS_KEY']

    access_key = setting('GS_ACCESS_KEY_ID')
    secret_key = setting('GS_SECRET_ACCESS_KEY')
    file_overwrite = setting('GS_FILE_OVERWRITE', True)
    headers = setting('GS_HEADERS', {})
    bucket_name = setting('GS_BUCKET_NAME', None)
    auto_create_bucket = setting('GS_AUTO_CREATE_BUCKET', False)
    default_acl = setting('GS_DEFAULT_ACL', 'public-read')
    bucket_acl = setting('GS_BUCKET_ACL', default_acl)
    querystring_auth = setting('GS_QUERYSTRING_AUTH', True)
    querystring_expire = setting('GS_QUERYSTRING_EXPIRE', 3600)
    durable_reduced_availability = setting('GS_DURABLE_REDUCED_AVAILABILITY', False)
    location = setting('GS_LOCATION', '')
    custom_domain = setting('GS_CUSTOM_DOMAIN')
    calling_format = setting('GS_CALLING_FORMAT', SubdomainCallingFormat())
    secure_urls = setting('GS_SECURE_URLS', True)
    file_name_charset = setting('GS_FILE_NAME_CHARSET', 'utf-8')
    gzip = setting('GS_IS_GZIPPED', False)
    preload_metadata = setting('GS_PRELOAD_METADATA', False)
    gzip_content_types = setting('GS_GZIP_CONTENT_TYPES', (
        'text/css',
        'application/javascript',
        'application/x-javascript',
    ))
    url_protocol = setting('GS_URL_PROTOCOL', 'http:')
    host = setting('GS_HOST', GSConnection.DefaultHost)

    def _get_connection_kwargs(self):
        kwargs = super(GSBotoStorage, self)._get_connection_kwargs()
        del kwargs['security_token']
        return kwargs

    def _save_content(self, key, content, headers):
        # only pass backwards incompatible arguments if they vary from the default
        options = {}
        if self.encryption:
            options['encrypt_key'] = self.encryption
        key.set_contents_from_file(content, headers=headers,
                                   policy=self.default_acl,
                                   rewind=True, **options)

    def _get_or_create_bucket(self, name):
        """
        Retrieves a bucket if it exists, otherwise creates it.
        """
        if self.durable_reduced_availability:
            storage_class = 'DURABLE_REDUCED_AVAILABILITY'
        else:
            storage_class = 'STANDARD'
        try:
            return self.connection.get_bucket(name,
                                              validate=self.auto_create_bucket)
        except self.connection_response_error:
            if self.auto_create_bucket:
                bucket = self.connection.create_bucket(name, storage_class=storage_class)
                bucket.set_acl(self.bucket_acl)
                return bucket
            raise ImproperlyConfigured("Bucket %s does not exist. Buckets "
                                       "can be automatically created by "
                                       "setting GS_AUTO_CREATE_BUCKET to "
                                       "``True``." % name)
