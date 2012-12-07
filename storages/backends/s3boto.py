import os
import mimetypes

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO  # noqa

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.utils.encoding import force_unicode, smart_str

try:
    from boto.s3.connection import S3Connection, SubdomainCallingFormat
    from boto.exception import S3ResponseError
    from boto.s3.key import Key
except ImportError:
    raise ImproperlyConfigured("Could not load Boto's S3 bindings.\n"
                               "See https://github.com/boto/boto")

ACCESS_KEY_NAME = getattr(settings, 'AWS_S3_ACCESS_KEY_ID', getattr(settings, 'AWS_ACCESS_KEY_ID', None))
SECRET_KEY_NAME = getattr(settings, 'AWS_S3_SECRET_ACCESS_KEY', getattr(settings, 'AWS_SECRET_ACCESS_KEY', None))
HEADERS = getattr(settings, 'AWS_HEADERS', {})
STORAGE_BUCKET_NAME = getattr(settings, 'AWS_STORAGE_BUCKET_NAME', None)
AUTO_CREATE_BUCKET = getattr(settings, 'AWS_AUTO_CREATE_BUCKET', False)
DEFAULT_ACL = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read')
BUCKET_ACL = getattr(settings, 'AWS_BUCKET_ACL', DEFAULT_ACL)
QUERYSTRING_AUTH = getattr(settings, 'AWS_QUERYSTRING_AUTH', True)
QUERYSTRING_EXPIRE = getattr(settings, 'AWS_QUERYSTRING_EXPIRE', 3600)
REDUCED_REDUNDANCY = getattr(settings, 'AWS_REDUCED_REDUNDANCY', False)
LOCATION = getattr(settings, 'AWS_LOCATION', '')
ENCRYPTION = getattr(settings, 'AWS_S3_ENCRYPTION', False)
CUSTOM_DOMAIN = getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', None)
CALLING_FORMAT = getattr(settings, 'AWS_S3_CALLING_FORMAT',
                         SubdomainCallingFormat())
SECURE_URLS = getattr(settings, 'AWS_S3_SECURE_URLS', True)
FILE_NAME_CHARSET = getattr(settings, 'AWS_S3_FILE_NAME_CHARSET', 'utf-8')
FILE_OVERWRITE = getattr(settings, 'AWS_S3_FILE_OVERWRITE', True)
FILE_BUFFER_SIZE = getattr(settings, 'AWS_S3_FILE_BUFFER_SIZE', 5242880)
IS_GZIPPED = getattr(settings, 'AWS_IS_GZIPPED', False)
PRELOAD_METADATA = getattr(settings, 'AWS_PRELOAD_METADATA', False)
GZIP_CONTENT_TYPES = getattr(settings, 'GZIP_CONTENT_TYPES', (
    'text/css',
    'application/javascript',
    'application/x-javascript',
))
URL_PROTOCOL = getattr(settings, 'AWS_S3_URL_PROTOCOL', 'http:')

# Backward-compatibility: given the anteriority of the SECURE_URL setting
# we fall back to https if specified in order to avoid the construction
# of unsecure urls.
if SECURE_URLS:
    URL_PROTOCOL = 'https:'

if IS_GZIPPED:
    from gzip import GzipFile


def safe_join(base, *paths):
    """
    A version of django.utils._os.safe_join for S3 paths.

    Joins one or more path components to the base path component
    intelligently. Returns a normalized version of the final path.

    The final path must be located inside of the base path component
    (otherwise a ValueError is raised).

    Paths outside the base path indicate a possible security
    sensitive operation.
    """
    from urlparse import urljoin
    base_path = force_unicode(base)
    base_path = base_path.rstrip('/')
    paths = [force_unicode(p) for p in paths]

    final_path = base_path
    for path in paths:
        final_path = urljoin(final_path.rstrip('/') + "/", path.rstrip("/"))

    # Ensure final_path starts with base_path and that the next character after
    # the final path is '/' (or nothing, in which case final_path must be
    # equal to base_path).
    base_path_len = len(base_path)
    if (not final_path.startswith(base_path) or
            final_path[base_path_len:base_path_len + 1] not in ('', '/')):
        raise ValueError('the joined path is located outside of the base path'
                         ' component')

    return final_path.lstrip('/')


class S3BotoStorage(Storage):
    """
    Amazon Simple Storage Service using Boto

    This storage backend supports opening files in read or write
    mode and supports streaming(buffering) data in chunks to S3
    when writing.
    """
    connection_class = S3Connection
    connection_response_error = S3ResponseError

    def __init__(self, bucket=STORAGE_BUCKET_NAME, access_key=None,
            secret_key=None, bucket_acl=BUCKET_ACL, acl=DEFAULT_ACL,
            headers=HEADERS, gzip=IS_GZIPPED,
            gzip_content_types=GZIP_CONTENT_TYPES,
            querystring_auth=QUERYSTRING_AUTH,
            querystring_expire=QUERYSTRING_EXPIRE,
            reduced_redundancy=REDUCED_REDUNDANCY,
            encryption=ENCRYPTION,
            custom_domain=CUSTOM_DOMAIN,
            secure_urls=SECURE_URLS,
            url_protocol=URL_PROTOCOL,
            location=LOCATION,
            file_name_charset=FILE_NAME_CHARSET,
            preload_metadata=PRELOAD_METADATA,
            calling_format=CALLING_FORMAT):
        self.bucket_acl = bucket_acl
        self.bucket_name = bucket
        self.acl = acl
        self.headers = headers
        self.preload_metadata = preload_metadata
        self.gzip = gzip
        self.gzip_content_types = gzip_content_types
        self.querystring_auth = querystring_auth
        self.querystring_expire = querystring_expire
        self.reduced_redundancy = reduced_redundancy
        self.encryption = encryption
        self.custom_domain = custom_domain
        self.secure_urls = secure_urls
        self.url_protocol = url_protocol
        self.location = location or ''
        self.location = self.location.lstrip('/')
        self.file_name_charset = file_name_charset
        self.calling_format = calling_format
        self._entries = {}
        if not access_key and not secret_key:
            access_key, secret_key = self._get_access_keys()
        self.connection = self.connection_class(access_key, secret_key,
            calling_format=self.calling_format)

    @property
    def bucket(self):
        """
        Get the current bucket. If there is no current bucket object
        create it.
        """
        if not hasattr(self, '_bucket'):
            self._bucket = self._get_or_create_bucket(self.bucket_name)
        return self._bucket

    @property
    def entries(self):
        """
        Get the locally cached files for the bucket.
        """
        if self.preload_metadata and not self._entries:
            self._entries = dict((self._decode_name(entry.key), entry)
                                for entry in self.bucket.list())
        return self._entries

    def _get_access_keys(self):
        """
        Gets the access keys to use when accessing S3. If none
        are provided to the class in the constructor or in the
        settings then get them from the environment variables.
        """
        access_key = ACCESS_KEY_NAME
        secret_key = SECRET_KEY_NAME
        if (access_key or secret_key) and (not access_key or not secret_key):
            # TODO: this seems to be broken
            access_key = os.environ.get(ACCESS_KEY_NAME)
            secret_key = os.environ.get(SECRET_KEY_NAME)

        if access_key and secret_key:
            # Both were provided, so use them
            return access_key, secret_key

        return None, None

    def _get_or_create_bucket(self, name):
        """Retrieves a bucket if it exists, otherwise creates it."""
        try:
            return self.connection.get_bucket(name,
                validate=AUTO_CREATE_BUCKET)
        except self.connection_response_error:
            if AUTO_CREATE_BUCKET:
                bucket = self.connection.create_bucket(name)
                bucket.set_acl(self.bucket_acl)
                return bucket
            raise ImproperlyConfigured("Bucket specified by "
                "AWS_STORAGE_BUCKET_NAME does not exist. "
                "Buckets can be automatically created by setting "
                "AWS_AUTO_CREATE_BUCKET=True")

    def _clean_name(self, name):
        """
        Cleans the name so that Windows style paths work
        """
        # Useful for windows' paths
        return os.path.normpath(name).replace('\\', '/')

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

    def _encode_name(self, name):
        return smart_str(name, encoding=self.file_name_charset)

    def _decode_name(self, name):
        return force_unicode(name, encoding=self.file_name_charset)

    def _compress_content(self, content):
        """Gzip a given string content."""
        zbuf = StringIO()
        zfile = GzipFile(mode='wb', compresslevel=6, fileobj=zbuf)
        try:
            zfile.write(content.read())
        finally:
            zfile.close()
        content.file = zbuf
        content.seek(0)
        return content

    def _open(self, name, mode='rb'):
        name = self._normalize_name(self._clean_name(name))
        f = S3BotoStorageFile(name, mode, self)
        if not f.key:
            raise IOError('File does not exist: %s' % name)
        return f

    def _save(self, name, content):
        cleaned_name = self._clean_name(name)
        name = self._normalize_name(cleaned_name)
        headers = self.headers.copy()
        content_type = getattr(content, 'content_type',
            mimetypes.guess_type(name)[0] or Key.DefaultContentType)

        # setting the content_type in the key object is not enough.
        self.headers.update({'Content-Type': content_type})

        if self.gzip and content_type in self.gzip_content_types:
            content = self._compress_content(content)
            headers.update({'Content-Encoding': 'gzip'})

        content.name = cleaned_name
        encoded_name = self._encode_name(name)
        key = self.bucket.get_key(encoded_name)
        if not key:
            key = self.bucket.new_key(encoded_name)
        if self.preload_metadata:
            self._entries[encoded_name] = key

        key.set_metadata('Content-Type', content_type)
        # only pass backwards incompatible arguments if they vary from the default
        kwargs = {}
        if self.encryption:
            kwargs['encrypt_key'] = self.encryption
        key.set_contents_from_file(content, headers=headers, policy=self.acl,
                                 reduced_redundancy=self.reduced_redundancy,
                                 rewind=True, **kwargs)
        return cleaned_name

    def delete(self, name):
        name = self._normalize_name(self._clean_name(name))
        self.bucket.delete_key(self._encode_name(name))

    def exists(self, name):
        name = self._normalize_name(self._clean_name(name))
        if self.entries:
            return name in self.entries
        k = self.bucket.new_key(self._encode_name(name))
        return k.exists()

    def listdir(self, name):
        name = self._normalize_name(self._clean_name(name))
        # for the bucket.list and logic below name needs to end in /
        # But for the root path "" we leave it as an empty string
        if name:
            name += '/'

        dirlist = self.bucket.list(self._encode_name(name))
        files = []
        dirs = set()
        base_parts = name.split("/")[:-1]
        for item in dirlist:
            parts = item.name.split("/")
            parts = parts[len(base_parts):]
            if len(parts) == 1:
                # File
                files.append(parts[0])
            elif len(parts) > 1:
                # Directory
                dirs.add(parts[0])
        return list(dirs), files

    def size(self, name):
        name = self._normalize_name(self._clean_name(name))
        if self.entries:
            entry = self.entries.get(name)
            if entry:
                return entry.size
            return 0
        return self.bucket.get_key(self._encode_name(name)).size

    def modified_time(self, name):
        try:
            from dateutil import parser, tz
        except ImportError:
            raise NotImplementedError()
        name = self._normalize_name(self._clean_name(name))
        entry = self.entries.get(name)
        # only call self.bucket.get_key() if the key is not found
        # in the preloaded metadata.
        if entry is None:
            entry = self.bucket.get_key(self._encode_name(name))
        # convert to string to date
        last_modified_date = parser.parse(entry.last_modified)
        # if the date has no timzone, assume UTC
        if last_modified_date.tzinfo == None:
            last_modified_date = last_modified_date.replace(tzinfo=tz.tzutc())
        # convert date to local time w/o timezone
        timezone = tz.gettz(settings.TIME_ZONE)
        return last_modified_date.astimezone(timezone).replace(tzinfo=None)

    def url(self, name):
        name = self._normalize_name(self._clean_name(name))
        if self.custom_domain:
            return "%s//%s/%s" % (self.url_protocol,
                                  self.custom_domain, name)
        return self.connection.generate_url(self.querystring_expire,
            method='GET', bucket=self.bucket.name, key=self._encode_name(name),
            query_auth=self.querystring_auth, force_http=not self.secure_urls)

    def get_available_name(self, name):
        """ Overwrite existing file with the same name. """
        if FILE_OVERWRITE:
            name = self._clean_name(name)
            return name
        return super(S3BotoStorage, self).get_available_name(name)


class S3BotoStorageFile(File):
    """
    The default file object used by the S3BotoStorage backend.

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
    # TODO: Read/Write (rw) mode may be a bit undefined at the moment. Needs testing.
    # TODO: When Django drops support for Python 2.5, rewrite to use the
    #       BufferedIO streams in the Python 2.6 io module.

    def __init__(self, name, mode, storage, buffer_size=FILE_BUFFER_SIZE):
        self._storage = storage
        self.name = name[len(self._storage.location):].lstrip('/')
        self._mode = mode
        self.key = storage.bucket.get_key(self._storage._encode_name(name))
        if not self.key and 'w' in mode:
            self.key = storage.bucket.new_key(storage._encode_name(name))
        self._is_dirty = False
        self._file = None
        self._multipart = None
        # 5 MB is the minimum part size (if there is more than one part).
        # Amazon allows up to 10,000 parts.  The default supports uploads
        # up to roughly 50 GB.  Increase the part size to accommodate
        # for files larger than this.
        self._write_buffer_size = buffer_size
        self._write_counter = 0

    @property
    def size(self):
        return self.key.size

    def _get_file(self):
        if self._file is None:
            self._file = StringIO()
            if 'r' in self._mode:
                self._is_dirty = False
                self.key.get_contents_to_file(self._file)
                self._file.seek(0)
            if self._storage.gzip and self.key.content_encoding == 'gzip':
                self._file = GzipFile(mode=self._mode, fileobj=self._file)
        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super(S3BotoStorageFile, self).read(*args, **kwargs)

    def write(self, *args, **kwargs):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        if self._multipart is None:
            provider = self.key.bucket.connection.provider
            upload_headers = {
                provider.acl_header: self._storage.acl
            }
            upload_headers.update(self._storage.headers)
            self._multipart = self._storage.bucket.initiate_multipart_upload(
                self.key.name,
                headers=upload_headers,
                reduced_redundancy=self._storage.reduced_redundancy
            )
        if self._write_buffer_size <= self._buffer_file_size:
            self._flush_write_buffer()
        return super(S3BotoStorageFile, self).write(*args, **kwargs)

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
            self._multipart.upload_part_from_file(
                self.file,
                self._write_counter,
                headers=self._storage.headers
            )
            self.file.close()
            self._file = None

    def close(self):
        if self._is_dirty:
            self._flush_write_buffer()
            self._multipart.complete_upload()
        else:
            if not self._multipart is None:
                self._multipart.cancel_upload()
        self.key.close()
