import os
import mimetypes

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.functional import curry

ACCESS_KEY_NAME = 'AWS_ACCESS_KEY_ID'
SECRET_KEY_NAME = 'AWS_SECRET_ACCESS_KEY'
HEADERS = 'AWS_HEADERS'

DEFAULT_ACL= getattr(settings, 'AWS_DEFAULT_ACL', 'public-read')
QUERYSTRING_ACTIVE= getattr(settings, 'AWS_QUERYSTRING_ACTIVE', False)
QUERYSTRING_EXPIRE= getattr(settings, 'AWS_QUERYSTRING_EXPIRE', 60)

try:
    from S3 import AWSAuthConnection, QueryStringAuthGenerator
except ImportError:
    raise ImproperlyConfigured, "Could not load amazon's S3 bindings.\
    \nSee http://developer.amazonwebservices.com/connect/entry.jspa?externalID=134"


class S3Storage(Storage):
    """Amazon Simple Storage Service"""

    def __init__(self, bucket=settings.AWS_STORAGE_BUCKET_NAME, 
            access_key=None, secret_key=None, acl=DEFAULT_ACL, 
            calling_format=settings.AWS_CALLING_FORMAT):
        self.bucket = bucket
        self.acl = acl

        if not access_key and not secret_key:
             access_key, secret_key = self._get_access_keys()

        self.connection = AWSAuthConnection(access_key, secret_key, 
                            calling_format=calling_format)
        self.generator = QueryStringAuthGenerator(access_key, secret_key, 
                            calling_format=calling_format, is_secure=False)
        self.generator.set_expires_in(QUERYSTRING_EXPIRE)
        
        self.headers = getattr(settings, HEADERS, {})

    def _get_access_keys(self):
        access_key = getattr(settings, ACCESS_KEY_NAME, None)
        secret_key = getattr(settings, SECRET_KEY_NAME, None)
        if (access_key or secret_key) and (not access_key or not secret_key):
            access_key = os.environ.get(ACCESS_KEY_NAME)
            secret_key = os.environ.get(SECRET_KEY_NAME)

        if access_key and secret_key:
            # Both were provided, so use them
            return access_key, secret_key

        return None, None

    def _get_connection(self):
        return AWSAuthConnection(*self._get_access_keys())

    def _put_file(self, name, content):
        content_type = mimetypes.guess_type(name)[0] or "application/x-octet-stream"
        self.headers.update({'x-amz-acl': self.acl, 'Content-Type': content_type})
        response = self.connection.put(self.bucket, name, content, self.headers)
        if response.http_response.status != 200:
            raise IOError("S3StorageError: %s" % response.message)

    def _open(self, name, mode='rb'):
        remote_file = S3StorageFile(name, self, mode=mode)
        return remote_file

    def _read(self, name, start_range=None, end_range=None):
        if start_range is None:
            headers = {}
        else:
            headers = {'Range': 'bytes=%s-%s' % (start_range, end_range)}
        response = self.connection.get(self.bucket, name, headers)
        if response.http_response.status != 200:
            raise IOError("S3StorageError: %s" % response.message)
        headers = response.http_response.msg
        return response.object.data, headers.get('etag', None), headers.get('content-range', None)
        
    def _save(self, name, content):
        content.open()
        if hasattr(content, 'chunks'):
            content_str = ''.join(chunk for chunk in content.chunks())
        else:
            content_str = content.read()
        self._put_file(name, content_str)
        return name
    
    def delete(self, name):
        response = self.connection.delete(self.bucket, name)
        if response.http_response.status != 204:
            raise IOError("S3StorageError: %s" % response.message)

    def exists(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        return response.status == 200

    def size(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        content_length = response.getheader('Content-Length')
        return content_length and int(content_length) or 0
    
    def url(self, name):
        if QUERYSTRING_ACTIVE:
            return self.generator.generate_url('GET', self.bucket, name)
        else:
            return self.generator.make_bare_url(self.bucket, name)

    ## UNCOMMENT BELOW IF NECESSARY
    #def get_available_name(self, name):
    #    """ Overwrite existing file with the same name. """
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
