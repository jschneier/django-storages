import os
import mimetypes

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured

try:
    from S3 import AWSAuthConnection, QueryStringAuthGenerator
except ImportError:
    raise ImproperlyConfigured, "Could not load amazon's S3 bindings.\
    \nSee http://developer.amazonwebservices.com/connect/entry.jspa?externalID=134"

ACCESS_KEY_NAME     = getattr(settings, 'AWS_ACCESS_KEY_ID', None)
SECRET_KEY_NAME     = getattr(settings, 'AWS_SECRET_ACCESS_KEY', None)
HEADERS             = getattr(settings, 'AWS_HEADERS', {})
DEFAULT_ACL         = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read')
QUERYSTRING_ACTIVE  = getattr(settings, 'AWS_QUERYSTRING_ACTIVE', False)
QUERYSTRING_EXPIRE  = getattr(settings, 'AWS_QUERYSTRING_EXPIRE', 60)
SECURE_URLS         = getattr(settings, 'AWS_S3_SECURE_URLS', False)
BUCKET_PREFIX       = getattr(settings, 'AWS_BUCKET_PREFIX', '')

IS_GZIPPED          = getattr(settings, 'AWS_IS_GZIPPED', False)
GZIP_CONTENT_TYPES  = getattr(settings, 'GZIP_CONTENT_TYPES', (
    'text/css',
    'application/javascript',
    'application/x-javascript'
))

if IS_GZIPPED:
    from gzip import GzipFile

class S3Storage(Storage):
    """Amazon Simple Storage Service"""

    def __init__(self, bucket=settings.AWS_STORAGE_BUCKET_NAME,
            access_key=None, secret_key=None, acl=DEFAULT_ACL,
            calling_format=settings.AWS_CALLING_FORMAT, encrypt=False,
            gzip=IS_GZIPPED, gzip_content_types=GZIP_CONTENT_TYPES):
        self.bucket = bucket
        self.acl = acl
        self.encrypt = encrypt
        self.gzip = gzip
        self.gzip_content_types = gzip_content_types
        
        if encrypt:
            try:
                import ezPyCrypto
            except ImportError:
                raise ImproperlyConfigured, "Could not load ezPyCrypto.\
                \nSee http://www.freenet.org.nz/ezPyCrypto/ to install it."
            self.crypto_key = ezPyCrypto.key

        if not access_key and not secret_key:
            access_key, secret_key = self._get_access_keys()

        self.connection = AWSAuthConnection(access_key, secret_key,
                            calling_format=calling_format)
        self.generator = QueryStringAuthGenerator(access_key, secret_key, 
                            calling_format=calling_format,
                            is_secure=SECURE_URLS)
        self.generator.set_expires_in(QUERYSTRING_EXPIRE)
        
        self.headers = HEADERS

    def _get_access_keys(self):
        access_key = ACCESS_KEY_NAME
        secret_key = SECRET_KEY_NAME
        if (access_key or secret_key) and (not access_key or not secret_key):
            access_key = os.environ.get(ACCESS_KEY_NAME)
            secret_key = os.environ.get(SECRET_KEY_NAME)

        if access_key and secret_key:
            # Both were provided, so use them
            return access_key, secret_key

        return None, None

    def _get_connection(self):
        return AWSAuthConnection(*self._get_access_keys())

    def _clean_name(self, name):
        # Useful for windows' paths
        return os.path.join(BUCKET_PREFIX, os.path.normpath(name).replace('\\', '/'))

    def _compress_string(self, s):
        """Gzip a given string."""
        zbuf = StringIO()
        zfile = GzipFile(mode='wb', compresslevel=6, fileobj=zbuf)
        zfile.write(s)
        zfile.close()
        return zbuf.getvalue()
        
    def _put_file(self, name, content):
        if self.encrypt:
        
            # Create a key object
            key = self.crypto_key()
        
            # Read in a public key
            fd = open(settings.CRYPTO_KEYS_PUBLIC, "rb")
            public_key = fd.read()
            fd.close()
        
            # import this public key
            key.importKey(public_key)
        
            # Now encrypt some text against this public key
            content = key.encString(content)
        
        content_type = mimetypes.guess_type(name)[0] or "application/x-octet-stream"
        
        if self.gzip and content_type in self.gzip_content_types:
            content = self._compress_string(content)
            self.headers.update({'Content-Encoding': 'gzip'})
        
        self.headers.update({
            'x-amz-acl': self.acl, 
            'Content-Type': content_type,
            'Content-Length' : len(content),
        })
        response = self.connection.put(self.bucket, name, content, self.headers)
        if response.http_response.status not in (200, 206):
            raise IOError("S3StorageError: %s" % response.message)

    def _open(self, name, mode='rb'):
        name = self._clean_name(name)
        remote_file = S3StorageFile(name, self, mode=mode)
        return remote_file

    def _read(self, name, start_range=None, end_range=None):
        name = self._clean_name(name)
        if start_range is None:
            headers = {}
        else:
            headers = {'Range': 'bytes=%s-%s' % (start_range, end_range)}
        response = self.connection.get(self.bucket, name, headers)
        if response.http_response.status not in (200, 206):
            raise IOError("S3StorageError: %s" % response.message)
        headers = response.http_response.msg
        
        if self.encrypt:
            # Read in a private key
            fd = open(settings.CRYPTO_KEYS_PRIVATE, "rb")
            private_key = fd.read()
            fd.close()
        
            # Create a key object, and auto-import private key
            key = self.crypto_key(private_key)
        
            # Decrypt this file
            response.object.data = key.decString(response.object.data)
        
        return response.object.data, headers.get('etag', None), headers.get('content-range', None)
        
    def _save(self, name, content):
        name = self._clean_name(name)
        content.open()
        if hasattr(content, 'chunks'):
            content_str = ''.join(chunk for chunk in content.chunks())
        else:
            content_str = content.read()
        self._put_file(name, content_str)
        return name
    
    def delete(self, name):
        name = self._clean_name(name)
        response = self.connection.delete(self.bucket, name)
        if response.http_response.status != 204:
            raise IOError("S3StorageError: %s" % response.message)

    def exists(self, name):
        name = self._clean_name(name)
        response = self.connection._make_request('HEAD', self.bucket, name)
        return response.status == 200

    def size(self, name):
        name = self._clean_name(name)
        response = self.connection._make_request('HEAD', self.bucket, name)
        content_length = response.getheader('Content-Length')
        return content_length and int(content_length) or 0
    
    def url(self, name):
        name = self._clean_name(name)
        if QUERYSTRING_ACTIVE:
            return self.generator.generate_url('GET', self.bucket, name)
        else:
            return self.generator.make_bare_url(self.bucket, name)

    ## UNCOMMENT BELOW IF NECESSARY
    #def get_available_name(self, name):
    #    """ Overwrite existing file with the same name. """
    #    name = self._clean_name(name)
    #    return name


class S3StorageFile(File):
    def __init__(self, name, storage, mode):
        self._name = name
        self._storage = storage
        self._mode = mode
        self._is_dirty = False
        self.file = StringIO()
        self.start_range = 0
    
    @property
    def size(self):
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self._name)
        return self._size

    def read(self, num_bytes=None):
        if num_bytes is None:
            args = []
            self.start_range = 0
        else:
            args = [self.start_range, self.start_range+num_bytes-1]
        data, etags, content_range = self._storage._read(self._name, *args)
        if content_range is not None:
            current_range, size = content_range.split(' ', 1)[1].split('/', 1)
            start_range, end_range = current_range.split('-', 1)
            self._size, self.start_range = int(size), int(end_range)+1
        self.file = StringIO(data)
        return self.file.getvalue()

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            self._storage._put_file(self._name, self.file.getvalue())
        self.file.close()
