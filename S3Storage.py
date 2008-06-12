from mimetypes import guess_type
import os

from django.core.exceptions import ImproperlyConfigured
from django.core.filestorage.base import Storage, RemoteFile
from django.core.filestorage.filesystem import FileSystemStorage
from django.utils.functional import curry
from django.conf import settings

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

    def _put_file(self, filename, raw_contents):
        content_type = guess_type(filename)[0] or "application/x-octet-stream"
        self.headers.update({'x-amz-acl':  self.acl, 'Content-Type': content_type})
        response = self.connection.put(self.bucket, filename, raw_contents, self.headers)

    def url(self, filename):
        return self.generator.make_bare_url(self.bucket, filename)
    
    path = url

    def filesize(self, filename):
        response = self.connection.make_request('HEAD', self.bucket, filename)
        return int(response.getheader('Content-Length'))

    def open(self, filename, mode='rb'):
        response = self.connection.get(self.bucket, filename)
        writer = curry(self._put_file, filename)
        return RemoteFile(self, response.object.data, mode, writer)

    def exists(self, filename):
        response = self.connection.make_request('HEAD', self.bucket, filename)
        return response.status == 200

    def save(self, filename, raw_contents):
        filename = self.get_available_filename(filename)
        self._put_file(filename, raw_contents)
        return filename
    
    ## UNCOMMENT BELOW IF NECESSARY
    
    #def delete(self, filename):
    #    """ Do not delete default images. """
    #    if not filename.endswith('default.jpg') and not filename.endswith('guest.jpg'):
    #        self.connection.delete(self.bucket, filename)

    #def get_available_filename(self, filename):
    #    """ Overwrite existing file with the same name. """
    #    return filename