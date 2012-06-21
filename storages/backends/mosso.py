"""
Custom storage for django with Mosso Cloud Files backend.
Created by Rich Leland <rich@richleland.com>.
"""
import os
import warnings
warnings.simplefilter('always', PendingDeprecationWarning)
warnings.warn("The mosso module will be deprecated in version 1.2 of "
              "django-storages. The CloudFiles code has been moved into"
              "django-cumulus at http://github.com/richleland/django-cumulus.",
              PendingDeprecationWarning)

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files import File
from django.core.files.storage import Storage
from django.utils.text import get_valid_filename

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

try:
    import cloudfiles
    from cloudfiles.errors import NoSuchObject
except ImportError:
    raise ImproperlyConfigured("Could not load cloudfiles dependency. See "
                               "http://www.mosso.com/cloudfiles.jsp.")

# TODO: implement TTL into cloudfiles methods
TTL = getattr(settings, 'CLOUDFILES_TTL', 600)
CONNECTION_KWARGS = getattr(settings, 'CLOUDFILES_CONNECTION_KWARGS', {})
SSL = getattr(settings, 'CLOUDFILES_SSL', False)


def cloudfiles_upload_to(self, filename):
    """
    Simple, custom upload_to because Cloud Files doesn't support
    nested containers (directories).

    Actually found this out from @minter:
    @richleland The Cloud Files APIs do support pseudo-subdirectories, by
    creating zero-byte files with type application/directory.

    May implement in a future version.
    """
    return get_valid_filename(filename)


class CloudFilesStorage(Storage):
    """
    Custom storage for Mosso Cloud Files.
    """
    default_quick_listdir = True

    def __init__(self,
                 username=settings.CLOUDFILES_USERNAME,
                 api_key=settings.CLOUDFILES_API_KEY,
                 container=settings.CLOUDFILES_CONTAINER,
                 connection_kwargs=CONNECTION_KWARGS):
        """
        Initialize the settings for the connection and container.
        """
        self.username = username
        self.api_key = api_key
        self.container_name = container
        self.connection_kwargs = connection_kwargs

    def __getstate__(self):
        """
        Return a picklable representation of the storage.
        """
        return dict(username=self.username,
                    api_key=self.api_key,
                    container_name=self.container_name,
                    connection_kwargs=self.connection_kwargs)

    def _get_connection(self):
        if not hasattr(self, '_connection'):
            self._connection = cloudfiles.get_connection(self.username,
                                    self.api_key, **self.connection_kwargs)
        return self._connection

    def _set_connection(self, value):
        self._connection = value

    connection = property(_get_connection, _set_connection)

    def _get_container(self):
        if not hasattr(self, '_container'):
            self.container = self.connection.get_container(
                                                        self.container_name)
        return self._container

    def _set_container(self, container):
        """
        Set the container, making it publicly available (on Limelight CDN) if
        it is not already.
        """
        if not container.is_public():
            container.make_public()
        if hasattr(self, '_container_public_uri'):
            delattr(self, '_container_public_uri')
        self._container = container

    container = property(_get_container, _set_container)

    def _get_container_url(self):
        if not hasattr(self, '_container_public_uri'):
            if SSL:
                self._container_public_uri = self.container.public_ssl_uri()
            else:
                self._container_public_uri = self.container.public_uri()
        return self._container_public_uri

    container_url = property(_get_container_url)

    def _get_cloud_obj(self, name):
        """
        Helper function to get retrieve the requested Cloud Files Object.
        """
        return self.container.get_object(name)

    def _open(self, name, mode='rb'):
        """
        Return the CloudFilesStorageFile.
        """
        return CloudFilesStorageFile(storage=self, name=name)

    def _save(self, name, content):
        """
        Use the Cloud Files service to write ``content`` to a remote file
        (called ``name``).
        """
        (path, last) = os.path.split(name)
        if path:
            try:
                self.container.get_object(path)
            except NoSuchObject:
                self._save(path, CloudStorageDirectory(path))

        cloud_obj = self.container.create_object(name)
        cloud_obj.size = content.size

        content.open()
        # If the content type is available, pass it in directly rather than
        # getting the cloud object to try to guess.
        if hasattr(content.file, 'content_type'):
            cloud_obj.content_type = content.file.content_type
        cloud_obj.send(content)
        content.close()
        return name

    def delete(self, name):
        """
        Deletes the specified file from the storage system.
        """
        # If the file exists, delete it.
        if self.exists(name):
            self.container.delete_object(name)

    def exists(self, name):
        """
        Returns True if a file referenced by the given name already exists in
        the storage system, or False if the name is available for a new file.
        """
        try:
            self._get_cloud_obj(name)
            return True
        except NoSuchObject:
            return False

    def listdir(self, path):
        """
        Lists the contents of the specified path, returning a 2-tuple; the
        first being an empty list of directories (not available for quick-
        listing), the second being a list of filenames.

        If the list of directories is required, use the full_listdir method.
        """
        files = []
        if path and not path.endswith('/'):
            path = '%s/' % path
        path_len = len(path)
        for name in self.container.list_objects(path=path):
            files.append(name[path_len:])
        return ([], files)

    def full_listdir(self, path):
        """
        Lists the contents of the specified path, returning a 2-tuple of lists;
        the first item being directories, the second item being files.

        On large containers, this may be a slow operation for root containers
        because every single object must be returned (cloudfiles does not
        provide an explicit way of listing directories).
        """
        dirs = set()
        files = []
        if path and not path.endswith('/'):
            path = '%s/' % path
        path_len = len(path)
        for name in self.container.list_objects(prefix=path):
            name = name[path_len:]
            slash = name[1:-1].find('/') + 1
            if slash:
                dirs.add(name[:slash])
            elif name:
                files.append(name)
        dirs = list(dirs)
        dirs.sort()
        return (dirs, files)

    def size(self, name):
        """
        Returns the total size, in bytes, of the file specified by name.
        """
        return self._get_cloud_obj(name).size

    def url(self, name):
        """
        Returns an absolute URL where the file's contents can be accessed
        directly by a web browser.
        """
        return '%s/%s' % (self.container_url, name)


class CloudStorageDirectory(File):
    """
    A File-like object that creates a directory at cloudfiles
    """

    def __init__(self, name):
        super(CloudStorageDirectory, self).__init__(StringIO(), name=name)
        self.file.content_type = 'application/directory'
        self.size = 0

    def __str__(self):
        return 'directory'

    def __nonzero__(self):
        return True

    def open(self, mode=None):
        self.seek(0)

    def close(self):
        pass


class CloudFilesStorageFile(File):
    closed = False

    def __init__(self, storage, name, *args, **kwargs):
        self._storage = storage
        super(CloudFilesStorageFile, self).__init__(file=None, name=name,
                                                    *args, **kwargs)
        self._pos = 0


    def _get_size(self):
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self.name)
        return self._size

    def _set_size(self, size):
        self._size = size

    size = property(_get_size, _set_size)

    def _get_file(self):
        if not hasattr(self, '_file'):
            self._file = self._storage._get_cloud_obj(self.name)
        return self._file

    def _set_file(self, value):
        if value is None:
            if hasattr(self, '_file'):
                del self._file
        else:
            self._file = value

    file = property(_get_file, _set_file)

    def read(self, num_bytes=None):
        if self._pos == self._get_size():
            return None
        if self._pos + num_bytes > self._get_size():
            num_bytes = self._get_size() - self._pos
        data = self.file.read(size=num_bytes or -1, offset=self._pos)
        self._pos += len(data)
        return data

    def open(self, *args, **kwargs):
        """
        Open the cloud file object.
        """
        self.file
        self._pos = 0

    def close(self, *args, **kwargs):
        self._pos = 0

    @property
    def closed(self):
        return not hasattr(self, '_file')

    def seek(self, pos):
        self._pos = pos


class ThreadSafeCloudFilesStorage(CloudFilesStorage):
    """
    Extends CloudFilesStorage to make it thread safer.

    As long as you don't pass container or cloud objects
    between threads, you'll be thread safe.

    Uses one cloudfiles connection per thread.
    """

    def __init__(self, *args, **kwargs):
        super(ThreadSafeCloudFilesStorage, self).__init__(*args, **kwargs)

        import threading
        self.local_cache = threading.local()

    def _get_connection(self):
        if not hasattr(self.local_cache, 'connection'):
            connection = cloudfiles.get_connection(self.username,
                                    self.api_key, **self.connection_kwargs)
            self.local_cache.connection = connection

        return self.local_cache.connection

    connection = property(_get_connection, CloudFilesStorage._set_connection)

    def _get_container(self):
        if not hasattr(self.local_cache, 'container'):
            container = self.connection.get_container(self.container_name)
            self.local_cache.container = container

        return self.local_cache.container

    container = property(_get_container, CloudFilesStorage._set_container)

