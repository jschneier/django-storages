# Django storage using libcloud providers
# Aymeric Barantal (mric at chamal.fr) 2011
#
import os

from django.conf import settings
from django.core.files.storage import Storage
from django.core.files.base import File
from django.core.exceptions import ImproperlyConfigured

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


try:
    from libcloud.storage.providers import get_driver
    from libcloud.storage.types import ObjectDoesNotExistError, Provider
except ImportError:
    raise ImproperlyConfigured("Could not load libcloud")


class LibCloudStorage(Storage):
    """Django storage derived class using apache libcloud to operate
    on supported providers"""
    def __init__(self, provider_name=None, option=None):
        if provider_name is None:
            provider_name = getattr(settings, 'DEFAULT_LIBCLOUD_PROVIDER', 'default')

        self.provider = settings.LIBCLOUD_PROVIDERS.get(provider_name)
        if not self.provider:
            raise ImproperlyConfigured(
                'LIBCLOUD_PROVIDERS %s not defined or invalid' % provider_name)
        try:
            provider_type = self.provider['type']
            if isinstance(provider_type, basestring):
                module_path, tag = provider_type.rsplit('.', 1)
                if module_path != 'libcloud.storage.types.Provider':
                    raise ValueError("Invalid module path")
                provider_type = getattr(Provider, tag)

            Driver = get_driver(provider_type)
            self.driver = Driver(
                self.provider['user'],
                self.provider['key'],
                )
        except Exception, e:
            raise ImproperlyConfigured(
                "Unable to create libcloud driver type %s: %s" % \
                (self.provider.get('type'), e))
        self.bucket = self.provider['bucket']   # Limit to one container

    def _get_bucket(self):
        """Helper to get bucket object (libcloud container)"""
        return self.driver.get_container(self.bucket)

    def _clean_name(self, name):
        """Clean name (windows directories)"""
        return os.path.normpath(name).replace('\\', '/')

    def _get_object(self, name):
        """Get object by its name. Return None if object not found"""
        clean_name = self._clean_name(name)
        try:
            return self.driver.get_object(self.bucket, clean_name)
        except ObjectDoesNotExistError:
            return None

    def delete(self, name):
        """Delete object on remote"""
        obj = self._get_object(name)
        if obj:
            return self.driver.delete_object(obj)
        else:
            raise Exception('Object to delete does not exists')

    def exists(self, name):
        obj = self._get_object(name)
        return True if obj else False

    def listdir(self, path='/'):
        """Lists the contents of the specified path,
        returning a 2-tuple of lists; the first item being
        directories, the second item being files.
        """
        container = self._get_bucket()
        objects = self.driver.list_container_objects(container)
        path = self._clean_name(path)
        if not path.endswith('/'):
            path = "%s/" % path
        files = []
        dirs = []
        # TOFIX: better algorithm to filter correctly
        # (and not depend on google-storage empty folder naming)
        for o in objects:
            if path == '/':
                if o.name.count('/') == 0:
                    files.append(o.name)
                elif o.name.count('/') == 1:
                    dir_name = o.name[:o.name.index('/')]
                    if not dir_name in dirs:
                        dirs.append(dir_name)
            elif o.name.startswith(path):
                if o.name.count('/') <= path.count('/'):
                    # TOFIX : special case for google storage with empty dir
                    if o.name.endswith('_$folder$'):
                        name = o.name[:-9]
                        name = name[len(path):]
                        dirs.append(name)
                    else:
                        name = o.name[len(path):]
                        files.append(name)
        return (dirs, files)

    def size(self, name):
        obj = self._get_object(name)
        if obj:
            return obj.size
        else:
            return -1

    def url(self, name):
        obj = self._get_object(name)
        return self.driver.get_object_cdn_url(obj)

    def _open(self, name, mode='rb'):
        remote_file = LibCloudFile(name, self, mode=mode)
        return remote_file

    def _read(self, name, start_range=None, end_range=None):
        obj = self._get_object(name)
        # TOFIX : we should be able to read chunk by chunk
        return self.driver.download_object_as_stream(obj, obj.size).next()

    def _save(self, name, file):
        self.driver.upload_object_via_stream(iter(file), self._get_bucket(), name)
        return name


class LibCloudFile(File):
    """File inherited class for libcloud storage objects read and write"""
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
            args = [self.start_range, self.start_range + num_bytes - 1]
        data = self._storage._read(self._name, *args)
        self.file = StringIO(data)
        return self.file.getvalue()

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            self._storage._save(self._name, self.file)
        self.file.close()
