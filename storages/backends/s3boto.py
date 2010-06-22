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
    from boto.s3.connection import S3Connection, S3ResponseError
    from boto.s3.key import Key
except ImportError:
    raise ImproperlyConfigured, "Could not load Boto's S3 bindings.\
    \nSee http://code.google.com/p/boto/"

ACCESS_KEY_NAME     = getattr(settings, 'AWS_ACCESS_KEY_ID', None)
SECRET_KEY_NAME     = getattr(settings, 'AWS_SECRET_ACCESS_KEY', None)
HEADERS             = getattr(settings, 'AWS_HEADERS', {})
STORAGE_BUCKET_NAME = getattr(settings, 'AWS_STORAGE_BUCKET_NAME', None)
AUTO_CREATE_BUCKET  = getattr(settings, 'AWS_AUTO_CREATE_BUCKET', True)
DEFAULT_ACL         = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read')
QUERYSTRING_AUTH    = getattr(settings, 'AWS_QUERYSTRING_AUTH', True)
QUERYSTRING_EXPIRE  = getattr(settings, 'AWS_QUERYSTRING_EXPIRE', 3600)
LOCATION            = getattr(settings, 'AWS_LOCATION', '')
IS_GZIPPED          = getattr(settings, 'AWS_IS_GZIPPED', False)
GZIP_CONTENT_TYPES  = getattr(settings, 'GZIP_CONTENT_TYPES', (
    'text/css',
    'application/javascript',
    'application/x-javascript'
))

if IS_GZIPPED:
    from gzip import GzipFile

class S3BotoStorage(Storage):
    """Amazon Simple Storage Service using Boto"""
    
    def __init__(self, bucket=STORAGE_BUCKET_NAME, access_key=None,
                       secret_key=None, acl=DEFAULT_ACL, headers=HEADERS,
                       gzip=IS_GZIPPED, gzip_content_types=GZIP_CONTENT_TYPES,
                       querystring_auth=QUERYSTRING_AUTH, querystring_expire=QUERYSTRING_EXPIRE):
        self.acl = acl
        self.headers = headers
        self.gzip = gzip
        self.gzip_content_types = gzip_content_types
        self.querystring_auth = querystring_auth
        self.querystring_expire = querystring_expire
        
        if not access_key and not secret_key:
             access_key, secret_key = self._get_access_keys()
        
        self.connection = S3Connection(access_key, secret_key)
        self.bucket = self._get_or_create_bucket(bucket)
        self.bucket.set_acl(self.acl)
    
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
    
    def _get_or_create_bucket(self, name):
        """Retrieves a bucket if it exists, otherwise creates it."""
        try:
            return self.connection.get_bucket(name)
        except S3ResponseError, e:
            if AUTO_CREATE_BUCKET:
                return self.connection.create_bucket(name)
            raise ImproperlyConfigured, ("Bucket specified by "
            "AWS_STORAGE_BUCKET_NAME does not exist. Buckets can be "
            "automatically created by setting AWS_AUTO_CREATE_BUCKET=True")
    
    def _clean_name(self, name):
        # Useful for windows' paths
        return os.path.normpath(name).replace('\\', '/')

    def _compress_content(self, content):
        """Gzip a given string."""
        zbuf = StringIO()
        zfile = GzipFile(mode='wb', compresslevel=6, fileobj=zbuf)
        zfile.write(content.read())
        zfile.close()
        content.file = zbuf
        return content
        
    def _open(self, name, mode='rb'):
        name = self._clean_name(name)
        return S3BotoStorageFile(name, mode, self)
    
    def _save(self, name, content):
        name = self._clean_name(name)
        headers = self.headers
        content_type = mimetypes.guess_type(name)[0] or Key.DefaultContentType            

        if self.gzip and content_type in self.gzip_content_types:
            content = self._compress_content(content)
            headers.update({'Content-Encoding': 'gzip'})

        headers.update({
            'Content-Type': content_type,
        })
        
        content.name = name
        k = self.bucket.get_key(name)
        if not k:
            k = self.bucket.new_key(name)
        k.set_contents_from_file(content, headers=headers, policy=self.acl)
        return name
    
    def delete(self, name):
        name = self._clean_name(name)
        self.bucket.delete_key(name)
    
    def exists(self, name):
        name = self._clean_name(name)
        k = self.bucket.new_key(name)
        return k.exists()
    
    def listdir(self, name):
        dirlist = self.bucket.list(name)
        files = []
        dirs = set()
        base_parts = name.split("/") if name else []
        for item in dirlist:
            parts = item.name.split("/")
            parts = parts[len(base_parts):]
            if len(parts) == 1:
                # File 
                files.append(parts[0])
            elif len(parts) > 1:
                # Directory
                dirs.add(parts[0])
        return list(dirs),files

    def size(self, name):
        name = self._clean_name(name)
        return self.bucket.get_key(name).size
    
    def url(self, name):
        name = self._clean_name(name)
        return self.connection.generate_url(self.querystring_expire, method='GET', \
                bucket=self.bucket.name, key=name, query_auth=self.querystring_auth)

    def get_available_name(self, name):
        """ Overwrite existing file with the same name. """
        name = self._clean_name(name)
        return name


class S3BotoStorageFile(File):
    def __init__(self, name, mode, storage):
        self._storage = storage
        self.name = name
        self._mode = mode
        self.key = storage.bucket.get_key(name)
        self._is_dirty = False
        self._file = None

    @property
    def size(self):
        return self.key.size

    @property
    def file(self):
        if self._file is None:
            self._file = StringIO()
            if 'r' in self._mode:
                self._is_dirty = False
                self.key.get_contents_to_file(self._file)
                self._file.seek(0)
        return self._file

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super(S3BotoStorageFile, self).read(*args, **kwargs)

    def write(self, *args, **kwargs):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self._is_dirty = True
        return super(S3BotoStorageFile, self).write(*args, **kwargs)

    def close(self):
        if self._is_dirty:
            self.key.set_contents_from_file(self._file, headers=self._storage.headers, policy=self._storage.acl)
        self.key.close()
