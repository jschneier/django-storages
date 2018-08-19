import mimetypes
import os.path
from datetime import datetime, timedelta
from tempfile import NamedTemporaryFile

from azure.common import AzureMissingResourceHttpError
from azure.storage import CloudStorageAccount
from azure.storage.blob import ContentSettings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

from storages.utils import setting


def clean_name(name):
    return os.path.normpath(name).replace("\\", "/")


def pad_left(n, width, pad="0"):
    return ((pad * width) + str(n))[-width:]


@deconstructible
class AzureStorageFile(File):

    def __init__(self, name, mode, storage):
        self._name = name
        self._mode = mode
        self._storage = storage
        self._is_dirty = False
        self._file = None

    def _get_file(self):
        if self._file is None:
            self._file = NamedTemporaryFile(
                suffix=".AzureBoto3StorageFile",
                dir=setting("FILE_UPLOAD_TEMP_DIR", None)
            )
            if 'r' in self._mode:
                self._is_dirty = False
                self._storage.connection.get_blob_to_path(container_name=self._storage.azure_container,
                                                          blob_name=self._name, file_path=self._file.name,
                                                          max_connections=setting("AZURE_READ_MAX_CONNECTIONS", 2))

                self._file.seek(0)
        return self._file

    file = property(_get_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super(AzureStorageFile, self).read(*args, **kwargs)

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        ret = super(AzureStorageFile, self).write(content)
        return ret

    def close(self):
        if self._is_dirty:
            self._storage.connection.create_blob_from_path(self._storage.azure_container, self._name, self._file.name)
        if self._file is not None:
            self._file.close()
            self._file = None


@deconstructible
class AzureStorage(Storage):
    account_key = setting("AZURE_ACCOUNT_KEY")
    account_name = setting("AZURE_ACCOUNT_NAME")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    buffer_size = setting('AZURE_FILE_BUFFER_SIZE', 4194304)
    max_memory_size = setting('AZURE_BLOB_MAX_MEMORY_SIZE', 0)
    querystring_auth = setting('AZURE_QUERYSTRING_AUTH', True)
    querystring_expire = setting('AZURE_QUERYSTRING_EXPIRE', 3600)

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            account = CloudStorageAccount(self.account_name, self.account_key)
            self._connection = account.create_block_blob_service()
        return self._connection

    @property
    def azure_protocol(self):
        if self.azure_ssl:
            return 'https'
        return 'http' if self.azure_ssl is not None else None

    def _open(self, name, mode="rb"):
        return AzureStorageFile(name, mode, self)

    def exists(self, file_name):
        return self.connection.exists(self.azure_container, file_name)

    def delete(self, name):
        try:
            self.connection.delete_blob(container_name=self.azure_container, blob_name=name)
        except AzureMissingResourceHttpError:
            pass

    def size(self, name):
        properties = self.connection.get_blob_properties(
            self.azure_container, name).properties
        return properties.content_length

    def _save(self, name, content):
        if hasattr(content.file, 'content_type'):
            content_type = content.file.content_type
        else:
            content_type = mimetypes.guess_type(name)[0]

        # if hasattr(content, 'chunks'):
            # content = BytesIO(b''.join(chunk for chunk in content.chunks()))
        content_settings = ContentSettings(content_type=content_type)
        self.connection.create_blob_from_stream(container_name=self.azure_container,
                                                blob_name=name,
                                                stream=content,
                                                content_settings=content_settings,
                                                max_connections=setting("AZURE_WRITE_MAX_CONNECTIONS", 2)
                                                )
        return name

    def _expire_at(self, expire):
            now = datetime.utcnow()
            now_plus_delta = now + timedelta(seconds=expire)
            now_plus_delta = now_plus_delta.replace(microsecond=0).isoformat() + 'Z'
            return now, now_plus_delta

    def url(self, name, expire=None, mode='r'):
        if self.querystring_auth and expire is None:
            expire = self.querystring_expire
        if hasattr(self.connection, 'make_blob_url'):
            sas_token = None
            make_blob_url_kwargs = {}
            if expire:
                now, now_plus_delta = self._expire_at(expire)
                sas_token = self.connection.generate_blob_shared_access_signature(self.azure_container,
                                                                                  name, 'r',
                                                                                  expiry=now_plus_delta)
                make_blob_url_kwargs['sas_token'] = sas_token

            if self.azure_protocol:
                make_blob_url_kwargs['protocol'] = self.azure_protocol
            return self.connection.make_blob_url(
                container_name=self.azure_container,
                blob_name=name,
                **make_blob_url_kwargs
            )
        else:
            return "{}{}/{}".format(setting('MEDIA_URL'), self.azure_container, name)

    def modified_time(self, name):
        properties = self.connection.get_blob_properties(
            self.azure_container, name).properties
        modified = properties.last_modified
        return modified
