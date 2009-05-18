import os

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.functional import curry
from django.core.exceptions import ImproperlyConfigured

try:
    from boto.s3.connection import S3Connection
    from boto.s3.key import Key
except ImportError:
    raise ImproperlyConfigured, "Could not load Boto's S3 bindings.\
    \nSee http://code.google.com/p/boto/"

ACCESS_KEY_NAME = 'AWS_ACCESS_KEY_ID'
SECRET_KEY_NAME = 'AWS_SECRET_ACCESS_KEY'
AWS_HEADERS     = 'AWS_HEADERS'
AWS_BUCKET_NAME = 'AWS_STORAGE_BUCKET_NAME'

AWS_BUCKET_PREFIX = getattr(settings, AWS_BUCKET_NAME, {})


class S3BotoStorage(Storage):
    """Amazon Simple Storage Service using Boto"""
    
    def __init__(self, bucket="root", bucketprefix=AWS_BUCKET_PREFIX, 
            access_key=None, secret_key=None, acl='public-read'):
        self.acl = acl
        
        if not access_key and not secret_key:
             access_key, secret_key = self._get_access_keys()
        
        self.connection = S3Connection(access_key, secret_key)
        self.bucket = self.connection.create_bucket(bucketprefix + bucket)
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
    
    def _open(self, name, mode='rb'):
        return S3BotoStorageFile(name, mode, self)
    
    def _save(self, name, content):
        k = self.bucket.get_key(name)
        if not k:
            k = self.bucket.new_key(name)
        k.set_contents_from_file(content)
        return name
    
    def delete(self, name):
        self.bucket.delete_key(name)
    
    def exists(self, name):
        k = Key(self.bucket, name)
        return k.exists()
    
    def listdir(self, name):
        return [l.name for l in self.bucket.list() if not len(name) or l.name[:len(name)] == name]
    
    def size(self, name):
        return self.bucket.get_key(name).size
    
    def url(self, name):
        return self.bucket.get_key(name).generate_url(3600, method='GET')
    
    def get_available_name(self, name):
        """ Overwrite existing file with the same name. """
        return name


class S3BotoStorageFile(File):
    def __init__(self, name, mode, storage):
        self._storage = storage
        self._name = name
        self._mode = mode
        self.key = storage.bucket.get_key(name)
    
    def size(self):
        return self.key.size
    
    def read(self, *args, **kwargs):
        return self.key.read(*args, **kwargs)
    
    def write(self, content):
        self.key.set_contents_from_string(content)
    
    def close(self):
        self.key.close()
