import os
from mimetypes import guess_type

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
AWS_HEADERS = 'AWS_HEADERS'

try:
    from S3 import AWSAuthConnection, QueryStringAuthGenerator
except ImportError:
    raise ImproperlyConfigured, "Could not load amazon's S3 bindings.\
    \nSee http://developer.amazonwebservices.com/connect/entry.jspa?externalID=134"


class S3Storage(Storage):
    """Amazon Simple Storage Service"""

    def __init__(self, bucket=settings.AWS_STORAGE_BUCKET_NAME, 
            access_key=None, secret_key=None, acl='public-read', 
            calling_format=settings.AWS_CALLING_FORMAT):
        self.bucket = bucket
        self.acl = acl

        if not access_key and not secret_key:
             access_key, secret_key = self._get_access_keys()

        self.connection = AWSAuthConnection(access_key, secret_key, 
                            calling_format=calling_format)
        self.generator = QueryStringAuthGenerator(access_key, secret_key, 
                            calling_format=calling_format, is_secure=False)
        
        self.headers = getattr(settings, AWS_HEADERS, {})

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
        content_type = guess_type(name)[0] or "application/x-octet-stream"
        self.headers.update({'x-amz-acl':  self.acl, 'Content-Type': content_type})
        response = self.connection.put(self.bucket, name, content, self.headers)

    def _open(self, name, mode='rb'):
        response = self.connection.get(self.bucket, name)
        writer = curry(self._put_file, name)
        #print response.object.data
        remote_file = S3StorageFile(response.object.data, mode, writer)
        remote_file.size = self.size(name)
        return remote_file

    def _save(self, name, content):
        self._put_file(name, content.read())
        return name
    
    def delete(self, name):
        self.connection.delete(self.bucket, name)

    def exists(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        return response.status == 200

    def size(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        content_length = response.getheader('Content-Length')
        return content_length and int(content_length) or 0
    
    def url(self, name):
        return self.generator.make_bare_url(self.bucket, name)

    ## UNCOMMENT BELOW IF NECESSARY
    #def get_available_name(self, name):
    #    """ Overwrite existing file with the same name. """
    #    return name


class S3StorageFile(File):
    def __init__(self, data, mode, writer):
        self._mode = mode
        self._write_to_storage = writer
        self._is_dirty = False
        self.file = StringIO(data)

    def read(self, num_bytes=None):
        return self.file.getvalue()

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            self._write_to_storage(self.file.getvalue())
        self.file.close()
