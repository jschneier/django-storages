import os
from mimetypes import guess_type

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import Storage
from django.core.files.remote import RemoteFile
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

    def _put_file(self, name, raw_contents):
        content_type = guess_type(name)[0] or "application/x-octet-stream"
        self.headers.update({'x-amz-acl':  self.acl, 'Content-Type': content_type})
        response = self.connection.put(self.bucket, name, raw_contents, self.headers)

    def path(self, name):
        return self.generator.make_bare_url(self.bucket, name)
    
    def size(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        return int(response.getheader('Content-Length'))
    
    url = path
    
    def exists(self, name):
        response = self.connection._make_request('HEAD', self.bucket, name)
        return response.status == 200

    def _open(self, name, mode='rb'):
        response = self.connection.get(self.bucket, name)
        writer = curry(self._put_file, name)
        return RemoteFile(response.object.data, mode, writer)

    def save(self, name, raw_contents):
        name = self.get_available_filename(name)
        self._put_file(name, raw_contents)
        return name
    
    def delete(self, name):
        self.connection.delete(self.bucket, name)

    ## UNCOMMENT BELOW IF NECESSARY
    #def get_available_filename(self, name):
    #    """ Overwrite existing file with the same name. """
    #    return name
