import mimetypes
from datetime import datetime, timedelta
from tempfile import SpooledTemporaryFile

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import (
    BlobClient, BlobSasPermissions, ContainerClient, ContentSettings,
    generate_blob_sas,
)
from django.core.exceptions import SuspiciousOperation
from django.core.files.base import File
from django.utils import timezone
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_bytes

from storages.base import BaseStorage
from storages.utils import (
    clean_name, get_available_overwrite_name, safe_join, setting,
)


@deconstructible
class AzureStorageFile(File):

    def __init__(self, name, mode, storage):
        self.name = name
        self._mode = mode
        self._storage = storage
        self._is_dirty = False
        self._file = None
        self._path = storage._get_valid_path(name)

    def _get_file(self):
        if self._file is not None:
            return self._file

        file = SpooledTemporaryFile(
            max_size=self._storage.max_memory_size,
            suffix=".AzureStorageFile",
            dir=setting("FILE_UPLOAD_TEMP_DIR", None))

        if 'r' in self._mode or 'a' in self._mode:
            # I set max connection to 1 since spooledtempfile is
            # not seekable which is required if we use max_connections > 1
            download_stream = self._storage.client.download_blob(
                self._path, timeout=self._storage.timeout)
            download_stream.download_to_stream(file, max_concurrency=1)
        if 'r' in self._mode:
            file.seek(0)

        self._file = file
        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode and 'a' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super().read(*args, **kwargs)

    def write(self, content):
        if ('w' not in self._mode and
                '+' not in self._mode and
                'a' not in self._mode):
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        return super().write(force_bytes(content))

    def close(self):
        if self._file is None:
            return
        if self._is_dirty:
            self._file.seek(0)
            self._storage._save(self.name, self._file)
            self._is_dirty = False
        self._file.close()
        self._file = None


def _content_type(content):
    try:
        return content.file.content_type
    except AttributeError:
        pass
    try:
        return content.content_type
    except AttributeError:
        pass
    return None


def _get_valid_path(s):
    # A blob name:
    #   * must not end with dot or slash
    #   * can contain any character
    #   * must escape URL reserved characters
    #     (not needed here since the azure client will do that)
    s = s.strip('./')
    if len(s) > _AZURE_NAME_MAX_LEN:
        raise ValueError(
            "File name max len is %d" % _AZURE_NAME_MAX_LEN)
    if not len(s):
        raise ValueError(
            "File name must contain one or more "
            "printable characters")
    if s.count('/') > 256:
        raise ValueError(
            "File name must not contain "
            "more than 256 slashes")
    return s


# Max len according to azure's docs
_AZURE_NAME_MAX_LEN = 1024


@deconstructible
class AzureStorage(BaseStorage):
    def __init__(self, **settings):
        super().__init__(**settings)
        self._client = None

    def get_default_settings(self):
        return {
            "account_name": setting("AZURE_ACCOUNT_NAME"),
            "account_key": setting("AZURE_ACCOUNT_KEY"),
            "object_parameters": setting("AZURE_OBJECT_PARAMETERS", {}),
            "azure_container": setting("AZURE_CONTAINER"),
            "azure_ssl": setting("AZURE_SSL", True),
            "upload_max_conn": setting("AZURE_UPLOAD_MAX_CONN", 2),
            "timeout": setting('AZURE_CONNECTION_TIMEOUT_SECS', 20),
            "max_memory_size": setting('AZURE_BLOB_MAX_MEMORY_SIZE', 2*1024*1024),
            "expiration_secs": setting('AZURE_URL_EXPIRATION_SECS'),
            "overwrite_files": setting('AZURE_OVERWRITE_FILES', False),
            "location": setting('AZURE_LOCATION', ''),
            "default_content_type": 'application/octet-stream',
            "cache_control": setting("AZURE_CACHE_CONTROL"),
            "sas_token": setting('AZURE_SAS_TOKEN'),
            "custom_domain": setting('AZURE_CUSTOM_DOMAIN'),
            "connection_string": setting('AZURE_CONNECTION_STRING'),
            "token_credential": setting('AZURE_TOKEN_CREDENTIAL'),
        }

    def _container_client(self, custom_domain=None, connection_string=None):
        if custom_domain is None:
            account_domain = "blob.core.windows.net"
        else:
            account_domain = custom_domain
        if connection_string is None:
            connection_string = "{}://{}.{}".format(
                self.azure_protocol,
                self.account_name,
                account_domain)
        credential = None
        if self.account_key:
            credential = self.account_key
        elif self.sas_token:
            credential = self.sas_token
        elif self.token_credential:
            credential = self.token_credential
        return ContainerClient(
            connection_string,
            self.azure_container,
            credential=credential)

    @property
    def client(self):
        if self._client is None:
            self._client = self._container_client(
                custom_domain=self.custom_domain,
                connection_string=self.connection_string)
        return self._client

    @property
    def azure_protocol(self):
        if self.azure_ssl:
            return 'https'
        else:
            return 'http'

    def _normalize_name(self, name):
        try:
            return safe_join(self.location, name)
        except ValueError:
            raise SuspiciousOperation("Attempted access to '%s' denied." % name)

    def _get_valid_path(self, name):
        # Must be idempotent
        return _get_valid_path(
            self._normalize_name(
                clean_name(name)))

    def _open(self, name, mode="rb"):
        return AzureStorageFile(name, mode, self)

    def get_available_name(self, name, max_length=_AZURE_NAME_MAX_LEN):
        """
        Returns a filename that's free on the target storage system, and
        available for new content to be written to.
        """
        name = clean_name(name)
        if self.overwrite_files:
            return get_available_overwrite_name(name, max_length)
        return super().get_available_name(name, max_length)

    def exists(self, name):
        blob_client = self.client.get_blob_client(self._get_valid_path(name))
        try:
            blob_client.get_blob_properties()
            return True
        except ResourceNotFoundError:
            return False

    def delete(self, name):
        try:
            self.client.delete_blob(
                self._get_valid_path(name),
                timeout=self.timeout)
        except ResourceNotFoundError:
            pass

    def size(self, name):
        blob_client = self.client.get_blob_client(self._get_valid_path(name))
        properties = blob_client.get_blob_properties(timeout=self.timeout)
        return properties.size

    def _save(self, name, content):
        cleaned_name = clean_name(name)
        name = self._get_valid_path(name)
        params = self._get_content_settings_parameters(name, content)

        # Unwrap django file (wrapped by parent's save call)
        if isinstance(content, File):
            content = content.file

        content.seek(0)
        self.client.upload_blob(
            name,
            content,
            content_settings=ContentSettings(**params),
            max_concurrency=self.upload_max_conn,
            timeout=self.timeout,
            overwrite=self.overwrite_files)
        return cleaned_name

    def _expire_at(self, expire):
        # azure expects time in UTC
        return datetime.utcnow() + timedelta(seconds=expire)

    def url(self, name, expire=None):
        name = self._get_valid_path(name)

        if expire is None:
            expire = self.expiration_secs

        credential = None
        if expire:
            sas_token = generate_blob_sas(
                self.account_name,
                self.azure_container,
                name,
                account_key=self.account_key,
                permission=BlobSasPermissions(read=True),
                expiry=self._expire_at(expire))
            credential = sas_token

        container_blob_url = self.client.get_blob_client(name).url
        return BlobClient.from_blob_url(container_blob_url, credential=credential).url

    def _get_content_settings_parameters(self, name, content=None):
        params = {}

        guessed_type, content_encoding = mimetypes.guess_type(name)
        content_type = (
            _content_type(content) or
            guessed_type or
            self.default_content_type)

        params['cache_control'] = self.cache_control
        params['content_type'] = content_type
        params['content_encoding'] = content_encoding

        params.update(self.get_object_parameters(name))
        return params

    def get_object_parameters(self, name):
        """
        Returns a dictionary that is passed to content settings. Override this
        method to adjust this on a per-object basis to set e.g ContentDisposition.

        By default, returns the value of AZURE_OBJECT_PARAMETERS.
        """
        return self.object_parameters.copy()

    def get_modified_time(self, name):
        """
        Returns an (aware) datetime object containing the last modified time if
        USE_TZ is True, otherwise returns a naive datetime in the local timezone.
        """
        properties = self.client.get_blob_properties(
            self._get_valid_path(name),
            timeout=self.timeout)
        if not setting('USE_TZ', False):
            return timezone.make_naive(properties.last_modified)

        tz = timezone.get_current_timezone()
        if timezone.is_naive(properties.last_modified):
            return timezone.make_aware(properties.last_modified, tz)

        # `last_modified` is in UTC time_zone, we
        # must convert it to settings time_zone
        return properties.last_modified.astimezone(tz)

    def modified_time(self, name):
        """Returns a naive datetime object containing the last modified time."""
        mtime = self.get_modified_time(name)
        if timezone.is_naive(mtime):
            return mtime
        return timezone.make_naive(mtime)

    def list_all(self, path=''):
        """Return all files for a given path"""
        if path:
            path = self._get_valid_path(path)
        if path and not path.endswith('/'):
            path += '/'
        # XXX make generator, add start, end
        return [
            blob.name
            for blob in self.client.list_blobs(
                name_starts_with=path,
                timeout=self.timeout)]

    def listdir(self, path=''):
        """
        Return directories and files for a given path.
        Leave the path empty to list the root.
        Order of dirs and files is undefined.
        """
        files = []
        dirs = set()
        for name in self.list_all(path):
            n = name[len(path):]
            if '/' in n:
                dirs.add(n.split('/', 1)[0])
            else:
                files.append(n)
        return list(dirs), files

    def get_name_max_len(self):
        max_len = _AZURE_NAME_MAX_LEN - len(self._get_valid_path('foo')) - len('foo')
        if not self.overwrite_files:
            max_len -= len('_1234567')
        return max_len
