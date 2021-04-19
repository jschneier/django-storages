import io
import mimetypes
import os
import posixpath
import tempfile
import threading
from datetime import datetime, timedelta
from gzip import GzipFile
from tempfile import SpooledTemporaryFile
from urllib.parse import parse_qsl, urlsplit

from django.contrib.staticfiles.storage import ManifestFilesMixin
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.core.files.base import File
from django.utils.deconstruct import deconstructible
from django.utils.encoding import filepath_to_uri
from django.utils.timezone import is_naive, make_naive

from storages.base import BaseStorage
from storages.utils import (
    check_location, get_available_overwrite_name, lookup_env, safe_join,
    setting, to_bytes,
)

try:
    import boto3.session
    from botocore.client import Config
    from botocore.exceptions import ClientError
    from botocore.signers import CloudFrontSigner
except ImportError as e:
    raise ImproperlyConfigured("Could not load Boto3's S3 bindings. %s" % e)


# NOTE: these are defined as functions so both can be tested
def _use_cryptography_signer():
    # https://cryptography.io as an RSA backend
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    def _cloud_front_signer_from_pem(key_id, pem):
        if isinstance(pem, str):
            pem = pem.encode('ascii')
        key = load_pem_private_key(
            pem, password=None, backend=default_backend())

        return CloudFrontSigner(
            key_id, lambda x: key.sign(x, padding.PKCS1v15(), hashes.SHA1()))

    return _cloud_front_signer_from_pem


def _use_rsa_signer():
    # https://stuvel.eu/rsa as an RSA backend
    import rsa

    def _cloud_front_signer_from_pem(key_id, pem):
        if isinstance(pem, str):
            pem = pem.encode('ascii')
        key = rsa.PrivateKey.load_pkcs1(pem)
        return CloudFrontSigner(key_id, lambda x: rsa.sign(x, key, 'SHA-1'))

    return _cloud_front_signer_from_pem


for _signer_factory in (_use_cryptography_signer, _use_rsa_signer):
    try:
        _cloud_front_signer_from_pem = _signer_factory()
        break
    except ImportError:
        pass
else:
    def _cloud_front_signer_from_pem(key_id, pem):
        raise ImproperlyConfigured(
            'An RSA backend is required for signing cloudfront URLs.\n'
            'Supported backends are packages: cryptography and rsa.')


@deconstructible
class S3Boto3StorageFile(File):
    """
    The default file object used by the S3Boto3Storage backend.

    This file implements file streaming using boto's multipart
    uploading functionality. The file can be opened in read or
    write mode.

    This class extends Django's File class. However, the contained
    data is only the data contained in the current buffer. So you
    should not access the contained file object directly. You should
    access the data via this class.

    Warning: This file *must* be closed using the close() method in
    order to properly write the file to S3. Be sure to close the file
    in your application.
    """

    def __init__(self, name, mode, storage, buffer_size=None):
        if 'r' in mode and 'w' in mode:
            raise ValueError("Can't combine 'r' and 'w' in mode.")
        self._storage = storage
        self.name = name[len(self._storage.location):].lstrip('/')
        self._mode = mode
        self._force_mode = (lambda b: b) if 'b' in mode else (lambda b: b.decode())
        self.obj = storage.bucket.Object(name)
        if 'w' not in mode:
            # Force early RAII-style exception if object does not exist
            self.obj.load()
        self._is_dirty = False
        self._raw_bytes_written = 0
        self._file = None
        self._multipart = None
        # 5 MB is the minimum part size (if there is more than one part).
        # Amazon allows up to 10,000 parts.  The default supports uploads
        # up to roughly 50 GB.  Increase the part size to accommodate
        # for files larger than this.
        self.buffer_size = buffer_size or setting('AWS_S3_FILE_BUFFER_SIZE', 5242880)
        self._write_counter = 0

    @property
    def size(self):
        return self.obj.content_length

    def _get_file(self):
        if self._file is None:
            self._file = SpooledTemporaryFile(
                max_size=self._storage.max_memory_size,
                suffix=".S3Boto3StorageFile",
                dir=setting("FILE_UPLOAD_TEMP_DIR")
            )
            if 'r' in self._mode:
                self._is_dirty = False
                self.obj.download_fileobj(self._file)
                self._file.seek(0)
            if self._storage.gzip and self.obj.content_encoding == 'gzip':
                self._file = GzipFile(mode=self._mode, fileobj=self._file, mtime=0.0)
        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return self._force_mode(super().read(*args, **kwargs))

    def readline(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return self._force_mode(super().readline(*args, **kwargs))

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        if self._multipart is None:
            self._multipart = self.obj.initiate_multipart_upload(
                **self._storage._get_write_parameters(self.obj.key)
            )
        if self.buffer_size <= self._buffer_file_size:
            self._flush_write_buffer()
        bstr = to_bytes(content)
        self._raw_bytes_written += len(bstr)
        return super().write(bstr)

    @property
    def _buffer_file_size(self):
        pos = self.file.tell()
        self.file.seek(0, os.SEEK_END)
        length = self.file.tell()
        self.file.seek(pos)
        return length

    def _flush_write_buffer(self):
        """
        Flushes the write buffer.
        """
        if self._buffer_file_size:
            self._write_counter += 1
            self.file.seek(0)
            part = self._multipart.Part(self._write_counter)
            part.upload(Body=self.file.read())
            self.file.seek(0)
            self.file.truncate()

    def _create_empty_on_close(self):
        """
        Attempt to create an empty file for this key when this File is closed if no bytes
        have been written and no object already exists on S3 for this key.

        This behavior is meant to mimic the behavior of Django's builtin FileSystemStorage,
        where files are always created after they are opened in write mode:

            f = storage.open("file.txt", mode="w")
            f.close()
        """
        assert "w" in self._mode
        assert self._raw_bytes_written == 0

        try:
            # Check if the object exists on the server; if so, don't do anything
            self.obj.load()
        except ClientError as err:
            if err.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
                self.obj.put(
                    Body=b"", **self._storage._get_write_parameters(self.obj.key)
                )
            else:
                raise

    def close(self):
        if self._is_dirty:
            self._flush_write_buffer()
            # TODO: Possibly cache the part ids as they're being uploaded
            # instead of requesting parts from server. For now, emulating
            # s3boto's behavior.
            parts = [{'ETag': part.e_tag, 'PartNumber': part.part_number}
                     for part in self._multipart.parts.all()]
            self._multipart.complete(
                MultipartUpload={'Parts': parts})
        else:
            if self._multipart is not None:
                self._multipart.abort()
            if 'w' in self._mode and self._raw_bytes_written == 0:
                self._create_empty_on_close()
        if self._file is not None:
            self._file.close()
            self._file = None


@deconstructible
class S3Boto3Storage(BaseStorage):
    """
    Amazon Simple Storage Service using Boto3

    This storage backend supports opening files in read or write
    mode and supports streaming(buffering) data in chunks to S3
    when writing.
    """
    default_content_type = 'application/octet-stream'
    # If config provided in init, signature_version and addressing_style settings/args are ignored.
    config = None

    # used for looking up the access and secret key from env vars
    access_key_names = ['AWS_S3_ACCESS_KEY_ID', 'AWS_ACCESS_KEY_ID']
    secret_key_names = ['AWS_S3_SECRET_ACCESS_KEY', 'AWS_SECRET_ACCESS_KEY']
    security_token_names = ['AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN']
    security_token = None

    def __init__(self, **settings):
        super().__init__(**settings)

        check_location(self)

        # Backward-compatibility: given the anteriority of the SECURE_URL setting
        # we fall back to https if specified in order to avoid the construction
        # of unsecure urls.
        if self.secure_urls:
            self.url_protocol = 'https:'

        self._bucket = None
        self._connections = threading.local()

        self.access_key, self.secret_key = self._get_access_keys()
        self.security_token = self._get_security_token()

        if not self.config:
            self.config = Config(
                s3={'addressing_style': self.addressing_style},
                signature_version=self.signature_version,
                proxies=self.proxies,
            )

    def get_cloudfront_signer(self, key_id, key):
        return _cloud_front_signer_from_pem(key_id, key)

    def get_default_settings(self):
        cloudfront_key_id = setting('AWS_CLOUDFRONT_KEY_ID')
        cloudfront_key = setting('AWS_CLOUDFRONT_KEY')
        if bool(cloudfront_key_id) ^ bool(cloudfront_key):
            raise ImproperlyConfigured(
                'Both AWS_CLOUDFRONT_KEY_ID and AWS_CLOUDFRONT_KEY must be '
                'provided together.'
            )

        if cloudfront_key_id:
            cloudfront_signer = self.get_cloudfront_signer(cloudfront_key_id, cloudfront_key)
        else:
            cloudfront_signer = None

        return {
            "access_key": setting('AWS_S3_ACCESS_KEY_ID', setting('AWS_ACCESS_KEY_ID')),
            "secret_key": setting('AWS_S3_SECRET_ACCESS_KEY', setting('AWS_SECRET_ACCESS_KEY')),
            "file_overwrite": setting('AWS_S3_FILE_OVERWRITE', True),
            "object_parameters": setting('AWS_S3_OBJECT_PARAMETERS', {}),
            "bucket_name": setting('AWS_STORAGE_BUCKET_NAME'),
            "querystring_auth": setting('AWS_QUERYSTRING_AUTH', True),
            "querystring_expire": setting('AWS_QUERYSTRING_EXPIRE', 3600),
            "signature_version": setting('AWS_S3_SIGNATURE_VERSION'),
            "location": setting('AWS_LOCATION', ''),
            "custom_domain": setting('AWS_S3_CUSTOM_DOMAIN'),
            "cloudfront_signer": cloudfront_signer,
            "addressing_style": setting('AWS_S3_ADDRESSING_STYLE'),
            "secure_urls": setting('AWS_S3_SECURE_URLS', True),
            "file_name_charset": setting('AWS_S3_FILE_NAME_CHARSET', 'utf-8'),
            "gzip": setting('AWS_IS_GZIPPED', False),
            "gzip_content_types": setting('GZIP_CONTENT_TYPES', (
                'text/css',
                'text/javascript',
                'application/javascript',
                'application/x-javascript',
                'image/svg+xml',
            )),
            "url_protocol": setting('AWS_S3_URL_PROTOCOL', 'http:'),
            "endpoint_url": setting('AWS_S3_ENDPOINT_URL'),
            "proxies": setting('AWS_S3_PROXIES'),
            "region_name": setting('AWS_S3_REGION_NAME'),
            "use_ssl": setting('AWS_S3_USE_SSL', True),
            "verify": setting('AWS_S3_VERIFY', None),
            "max_memory_size": setting('AWS_S3_MAX_MEMORY_SIZE', 0),
            "default_acl": setting('AWS_DEFAULT_ACL', None),
        }

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop('_connections', None)
        state.pop('_bucket', None)
        return state

    def __setstate__(self, state):
        state['_connections'] = threading.local()
        state['_bucket'] = None
        self.__dict__ = state

    @property
    def connection(self):
        connection = getattr(self._connections, 'connection', None)
        if connection is None:
            session = boto3.session.Session()
            self._connections.connection = session.resource(
                's3',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                aws_session_token=self.security_token,
                region_name=self.region_name,
                use_ssl=self.use_ssl,
                endpoint_url=self.endpoint_url,
                config=self.config,
                verify=self.verify,
            )
        return self._connections.connection

    @property
    def bucket(self):
        """
        Get the current bucket. If there is no current bucket object
        create it.
        """
        if self._bucket is None:
            self._bucket = self.connection.Bucket(self.bucket_name)
        return self._bucket

    def _get_access_keys(self):
        """
        Gets the access keys to use when accessing S3. If none is
        provided in the settings then get them from the environment
        variables.
        """
        access_key = self.access_key or lookup_env(S3Boto3Storage.access_key_names)
        secret_key = self.secret_key or lookup_env(S3Boto3Storage.secret_key_names)
        return access_key, secret_key

    def _get_security_token(self):
        """
        Gets the security token to use when accessing S3. Get it from
        the environment variables.
        """
        security_token = self.security_token or lookup_env(S3Boto3Storage.security_token_names)
        return security_token

    def _clean_name(self, name):
        """
        Cleans the name so that Windows style paths work
        """
        # Normalize Windows style paths
        clean_name = posixpath.normpath(name).replace('\\', '/')

        # os.path.normpath() can strip trailing slashes so we implement
        # a workaround here.
        if name.endswith('/') and not clean_name.endswith('/'):
            # Add a trailing slash as it was stripped.
            clean_name += '/'
        return clean_name

    def _normalize_name(self, name):
        """
        Normalizes the name so that paths like /path/to/ignored/../something.txt
        work. We check to make sure that the path pointed to is not outside
        the directory specified by the LOCATION setting.
        """
        try:
            return safe_join(self.location, name)
        except ValueError:
            raise SuspiciousOperation("Attempted access to '%s' denied." %
                                      name)

    def _compress_content(self, content):
        """Gzip a given string content."""
        content.seek(0)
        zbuf = io.BytesIO()
        #  The GZIP header has a modification time attribute (see http://www.zlib.org/rfc-gzip.html)
        #  This means each time a file is compressed it changes even if the other contents don't change
        #  For S3 this defeats detection of changes using MD5 sums on gzipped files
        #  Fixing the mtime at 0.0 at compression time avoids this problem
        with GzipFile(mode='wb', fileobj=zbuf, mtime=0.0) as zfile:
            zfile.write(to_bytes(content.read()))
        zbuf.seek(0)
        # Boto 2 returned the InMemoryUploadedFile with the file pointer replaced,
        # but Boto 3 seems to have issues with that. No need for fp.name in Boto3
        # so just returning the BytesIO directly
        return zbuf

    def _open(self, name, mode='rb'):
        name = self._normalize_name(self._clean_name(name))
        try:
            f = S3Boto3StorageFile(name, mode, self)
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 404:
                raise FileNotFoundError('File does not exist: %s' % name)
            raise  # Let it bubble up if it was some other error
        return f

    def _save(self, name, content):
        cleaned_name = self._clean_name(name)
        name = self._normalize_name(cleaned_name)
        params = self._get_write_parameters(name, content)

        if (self.gzip and
                params['ContentType'] in self.gzip_content_types and
                'ContentEncoding' not in params):
            content = self._compress_content(content)
            params['ContentEncoding'] = 'gzip'

        obj = self.bucket.Object(name)
        content.seek(0, os.SEEK_SET)
        obj.upload_fileobj(content, ExtraArgs=params)
        return cleaned_name

    def delete(self, name):
        name = self._normalize_name(self._clean_name(name))
        self.bucket.Object(name).delete()

    def exists(self, name):
        name = self._normalize_name(self._clean_name(name))
        try:
            self.connection.meta.client.head_object(Bucket=self.bucket_name, Key=name)
            return True
        except ClientError:
            return False

    def listdir(self, name):
        path = self._normalize_name(self._clean_name(name))
        # The path needs to end with a slash, but if the root is empty, leave
        # it.
        if path and not path.endswith('/'):
            path += '/'

        directories = []
        files = []
        paginator = self.connection.meta.client.get_paginator('list_objects')
        pages = paginator.paginate(Bucket=self.bucket_name, Delimiter='/', Prefix=path)
        for page in pages:
            for entry in page.get('CommonPrefixes', ()):
                directories.append(posixpath.relpath(entry['Prefix'], path))
            for entry in page.get('Contents', ()):
                files.append(posixpath.relpath(entry['Key'], path))
        return directories, files

    def size(self, name):
        name = self._normalize_name(self._clean_name(name))
        return self.bucket.Object(name).content_length

    def _get_write_parameters(self, name, content=None):
        params = {}

        _type, encoding = mimetypes.guess_type(name)
        content_type = getattr(content, 'content_type', None)
        content_type = content_type or _type or self.default_content_type

        params['ContentType'] = content_type
        if encoding:
            params['ContentEncoding'] = encoding

        params.update(self.get_object_parameters(name))

        if 'ACL' not in params and self.default_acl:
            params['ACL'] = self.default_acl

        return params

    def get_object_parameters(self, name):
        """
        Returns a dictionary that is passed to file upload. Override this
        method to adjust this on a per-object basis to set e.g ContentDisposition.

        By default, returns the value of AWS_S3_OBJECT_PARAMETERS.

        Setting ContentEncoding will prevent objects from being automatically gzipped.
        """
        return self.object_parameters.copy()

    def get_modified_time(self, name):
        """
        Returns an (aware) datetime object containing the last modified time if
        USE_TZ is True, otherwise returns a naive datetime in the local timezone.
        """
        name = self._normalize_name(self._clean_name(name))
        entry = self.bucket.Object(name)
        if setting('USE_TZ'):
            # boto3 returns TZ aware timestamps
            return entry.last_modified
        else:
            return make_naive(entry.last_modified)

    def modified_time(self, name):
        """Returns a naive datetime object containing the last modified time."""
        # If USE_TZ=False then get_modified_time will return a naive datetime
        # so we just return that, else we have to localize and strip the tz
        mtime = self.get_modified_time(name)
        return mtime if is_naive(mtime) else make_naive(mtime)

    def _strip_signing_parameters(self, url):
        # Boto3 does not currently support generating URLs that are unsigned. Instead we
        # take the signed URLs and strip any querystring params related to signing and expiration.
        # Note that this may end up with URLs that are still invalid, especially if params are
        # passed in that only work with signed URLs, e.g. response header params.
        # The code attempts to strip all query parameters that match names of known parameters
        # from v2 and v4 signatures, regardless of the actual signature version used.
        split_url = urlsplit(url)
        qs = parse_qsl(split_url.query, keep_blank_values=True)
        blacklist = {
            'x-amz-algorithm', 'x-amz-credential', 'x-amz-date',
            'x-amz-expires', 'x-amz-signedheaders', 'x-amz-signature',
            'x-amz-security-token', 'awsaccesskeyid', 'expires', 'signature',
        }
        filtered_qs = ((key, val) for key, val in qs if key.lower() not in blacklist)
        # Note: Parameters that did not have a value in the original query string will have
        # an '=' sign appended to it, e.g ?foo&bar becomes ?foo=&bar=
        joined_qs = ('='.join(keyval) for keyval in filtered_qs)
        split_url = split_url._replace(query="&".join(joined_qs))
        return split_url.geturl()

    def url(self, name, parameters=None, expire=None, http_method=None):
        # Preserve the trailing slash after normalizing the path.
        name = self._normalize_name(self._clean_name(name))
        if expire is None:
            expire = self.querystring_expire

        if self.custom_domain:
            url = "{}//{}/{}".format(
                self.url_protocol, self.custom_domain, filepath_to_uri(name))

            if self.querystring_auth and self.cloudfront_signer:
                expiration = datetime.utcnow() + timedelta(seconds=expire)

                return self.cloudfront_signer.generate_presigned_url(url, date_less_than=expiration)

            return url

        params = parameters.copy() if parameters else {}
        params['Bucket'] = self.bucket.name
        params['Key'] = name
        url = self.bucket.meta.client.generate_presigned_url('get_object', Params=params,
                                                             ExpiresIn=expire, HttpMethod=http_method)
        if self.querystring_auth:
            return url
        return self._strip_signing_parameters(url)

    def get_available_name(self, name, max_length=None):
        """Overwrite existing file with the same name."""
        name = self._clean_name(name)
        if self.file_overwrite:
            return get_available_overwrite_name(name, max_length)
        return super().get_available_name(name, max_length)


class S3StaticStorage(S3Boto3Storage):
    """Querystring auth must be disabled so that url() returns a consistent output."""
    querystring_auth = False


class S3ManifestStaticStorage(ManifestFilesMixin, S3StaticStorage):
    """Copy the file before saving for compatibility with ManifestFilesMixin
    which does not play nicely with boto3 automatically closing the file.

    See: https://github.com/boto/s3transfer/issues/80#issuecomment-562356142
    """

    def _save(self, name, content):
        content.seek(0)
        with tempfile.SpooledTemporaryFile() as tmp:
            tmp.write(content.read())
            return super()._save(name, tmp)
