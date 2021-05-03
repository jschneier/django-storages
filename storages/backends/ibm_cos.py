import tempfile
from .s3boto3 import S3Boto3Storage
from django.contrib.staticfiles.storage import ManifestFilesMixin
from storages.utils import setting

class IBMCloudObjectStorage(S3Boto3Storage):
    """
    IBM Cloud Object Storage support via inheriting from S3Boto3Storage class

    """

    # used for looking up the access and secret key from env vars
    access_key_names = ['IBM_COS_ACCESS_KEY_ID', 'IBM_ACCESS_KEY_ID']
    secret_key_names = ['IBM_COS_SECRET_ACCESS_KEY', 'IBM_SECRET_ACCESS_KEY']
    security_token_names = ['IBM_SESSION_TOKEN', 'IBM_SECURITY_TOKEN']



    def get_default_settings(self):
        return {
            "access_key": setting('IBM_COS_ACCESS_KEY_ID', setting('IBM_ACCESS_KEY_ID')),
            "secret_key": setting('IBM_COS_SECRET_ACCESS_KEY', setting('IBM_SECRET_ACCESS_KEY')),
            "file_overwrite": setting('IBM_COS_FILE_OVERWRITE', True),
            "object_parameters": setting('IBM_COS_OBJECT_PARAMETERS', {}),
            "bucket_name": setting('IBM_COS_BUCKET_NAME'),
            "querystring_auth": setting('IBM_QUERYSTRING_AUTH', True),
            "querystring_expire": setting('IBM_QUERYSTRING_EXPIRE', 3600),
            "signature_version": setting('IBM_COS_SIGNATURE_VERSION'),
            "location": setting('IBM_LOCATION', ''),
            "custom_domain": setting('IBM_COS_CUSTOM_DOMAIN'),
            "addressing_style": setting('IBM_COS_ADDRESSING_STYLE'),
            "secure_urls": setting('IBM_COS_SECURE_URLS', True),
            "file_name_charset": setting('IBM_COS_FILE_NAME_CHARSET', 'utf-8'),
            "gzip": setting('IBM_IS_GZIPPED', False),
            "gzip_content_types": setting('GZIP_CONTENT_TYPES', (
                'text/css',
                'text/javascript',
                'application/javascript',
                'application/x-javascript',
                'image/svg+xml',
            )),
            "url_protocol": setting('IBM_COS_URL_PROTOCOL', 'http:'),
            "endpoint_url": setting('IBM_COS_ENDPOINT_URL'),
            "proxies": setting('IBM_COS_PROXIES'),
            "region_name": setting('IBM_COS_REGION_NAME'),
            "use_ssl": setting('IBM_COS_USE_SSL', True),
            "verify": setting('IBM_COS_VERIFY', None),
            "max_memory_size": setting('IBM_COS_MAX_MEMORY_SIZE', 0),
            "default_acl": setting('IBM_DEFAULT_ACL', None),
        }

class IBMCOSStaticStorage(IBMCloudObjectStorage):
    """Querystring auth must be disabled so that url() returns a consistent output."""
    querystring_auth = False

class IBMCOSManifestStaticStorage(ManifestFilesMixin, IBMCOSStaticStorage):
    """Copy the file before saving for compatibility with ManifestFilesMixin
    which does not play nicely with boto3 automatically closing the file.

    See: https://github.com/boto/s3transfer/issues/80#issuecomment-562356142
    """

    def _save(self, name, content):
        content.seek(0)
        with tempfile.SpooledTemporaryFile() as tmp:
            tmp.write(content.read())
            return super()._save(name, tmp)
