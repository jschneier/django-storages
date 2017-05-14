from datetime import datetime, timedelta
import os.path
import mimetypes
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from azure.storage import CloudStorageAccount
from storages.utils import setting
from tempfile import SpooledTemporaryFile
from django.core.files.base import File
from io import BytesIO

from azure.common import AzureMissingResourceHttpError
from azure.storage.blob import ContentSettings


def clean_name(name):
    return os.path.normpath(name).replace("\\", "/")


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
            self._file = SpooledTemporaryFile(
                max_size=self._storage.max_memory_size,
                suffix=".AzureBoto3StorageFile",
                dir=setting("FILE_UPLOAD_TEMP_DIR", None)
            )
            if 'r' in self._mode:
                self._is_dirty = False
                # I set max connection to 1 since spooledtempfile is not seekable which is required if we use
                # max_conection > 1
                self._storage.connection.get_blob_to_stream(container_name=self._storage.azure_container,
                                                            blob_name=self._name, stream=self._file,
                                                            max_connections=1)

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
        create_kwargs = {'container_name': self._storage.azure_container,
                         'blob_name': self._name,
                         'max_connections': setting("AZURE_MAX_CONNECTIONS", 2)
                         }
        if 'wb' in self._mode:
            # write binaries
            create_kwargs['blob'] = content
            self._storage.connection.create_blob_from_bytes(**create_kwargs)
        else:
            # write text
            create_kwargs['text'] = content
            self._storage.connection.create_blob_from_text(**create_kwargs)


@deconstructible
class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    max_memory_size = setting('AZURE_BLOB_MAX_MEMORY_SIZE', 0)

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

    def exists(self, name):
        return self.connection.exists(name)

    def delete(self, name):
        try:
            self.connection.delete_blob(container_name=self.azure_container, blob_name=name)
        except AzureMissingResourceHttpError:
            pass

    def size(self, name):
        properties = self.connection.get_blob_properties(
            self.azure_container, name).properties
        return properties["content_length"]

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
                                                content=content,
                                                content_settings=content_settings)
        return name

    def _expire_at(self, expire):
            now = datetime.utcnow()
            now_plus_delta = now + timedelta(seconds=expire)
            now_plus_delta = now_plus_delta.replace(microsecond=0).isoformat() + 'Z'
            return now, now_plus_delta

    def url(self, name, expire=None, mode='r'):
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
        modified = properties["last_modified"]
        return modified
