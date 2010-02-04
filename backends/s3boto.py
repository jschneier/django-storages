import os
import mimetypes

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.core.files.base import ContentFile
from django.utils.functional import curry
from django.core.exceptions import ImproperlyConfigured

try:
    from boto.s3.connection import S3Connection
    from boto.s3.key import Key
    from boto.exception import S3CreateError
except ImportError:
    raise ImproperlyConfigured, "Could not load Boto's S3 bindings.\
    \nSee http://code.google.com/p/boto/"

ACCESS_KEY_NAME = 'AWS_ACCESS_KEY_ID'
SECRET_KEY_NAME = 'AWS_SECRET_ACCESS_KEY'
HEADERS         = 'AWS_HEADERS'
BUCKET_NAME     = 'AWS_STORAGE_BUCKET_NAME'
DEFAULT_ACL     = 'AWS_DEFAULT_ACL'
QUERYSTRING_AUTH = 'AWS_QUERYSTRING_AUTH'
QUERYSTRING_EXPIRE = 'AWS_QUERYSTRING_EXPIRE'
IS_GZIPPED         = 'AWS_IS_GZIPPED'
LOCATION           = 'AWS_LOCATION'

BUCKET_PREFIX     = getattr(settings, BUCKET_NAME, {})
HEADERS           = getattr(settings, HEADERS, {})
DEFAULT_ACL       = getattr(settings, DEFAULT_ACL, 'public-read')
QUERYSTRING_AUTH  = getattr(settings, QUERYSTRING_AUTH, True)
QUERYSTRING_EXPIRE= getattr(settings, QUERYSTRING_EXPIRE, 3600)
IS_GZIPPED        = getattr(settings, IS_GZIPPED, False) 
GZIP_CONTENT_TYPES = (
    'text/css',
    'application/javascript',
    'application/x-javascript'
)
GZIP_CONTENT_TYPES = getattr(settings, 'GZIP_CONTENT_TYPES', GZIP_CONTENT_TYPES)
LOCATION          = getattr(settings, LOCATION, '')

if IS_GZIPPED:
    from gzip import GzipFile

class S3BotoStorage(Storage):
    """Amazon Simple Storage Service using Boto"""
    
    def __init__(self, bucket="root", bucketprefix=BUCKET_PREFIX, 
            access_key=None, secret_key=None, acl=DEFAULT_ACL, headers=HEADERS,
            gzip=IS_GZIPPED, gzip_content_types=GZIP_CONTENT_TYPES):


    def __init__(self, bucket="root", bucketprefix=BUCKET_PREFIX,
            access_key=None, secret_key=None, acl=DEFAULT_ACL, headers=HEADERS):

        self.acl = acl
        self.headers = headers
        self.gzip = gzip
        self.gzip_content_types = gzip_content_types
        

        if not access_key and not secret_key:
             access_key, secret_key = self._get_access_keys()

        self.connection = S3Connection(access_key, secret_key)
        bucket_name = bucketprefix + bucket
        try:
            self.bucket = self.connection.create_bucket(bucket_name, {}, LOCATION)
            self.bucket.set_acl(self.acl)
        except S3CreateError:
            # assuming we own it
            self.bucket = self.connection.get_bucket(bucket_name)

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

        if hasattr(content.file, 'content_type'):
            content_type = content.file.content_type
        else:
            content_type = mimetypes.guess_type(name)[0] or "application/x-octet-stream"
            
        if self.gzip and content_type in self.gzip_content_types:
            content = self._compress_content(content)
            headers.update({'Content-Encoding': 'gzip'})

        headers.update({
            'Content-Type': content_type,
            'Content-Length' : len(content),
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
        k = Key(self.bucket, name)
        return k.exists()

    def listdir(self, name):
        name = self._clean_name(name)
        return [l.name for l in self.bucket.list() if not len(name) or l.name[:len(name)] == name]

    def size(self, name):
        name = self._clean_name(name)
        return self.bucket.get_key(name).size

    def url(self, name):
        name = self._clean_name(name)
        if self.bucket.get_key(name) is None:
            return ''
        return self.bucket.get_key(name).generate_url(QUERYSTRING_EXPIRE, method='GET', query_auth=QUERYSTRING_AUTH)

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
        self.file = StringIO()

    @property
    def size(self):
        return self.key.size

    def read(self, *args, **kwargs):
        self.file = StringIO()
        self._is_dirty = False
        self.key.get_contents_to_file(self.file)
        return self.file.getvalue()

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            self.key.set_contents_from_string(self.file.getvalue(), headers=self._storage.headers, acl=self._storage.acl)
        self.key.close()
