from datetime import datetime, timedelta
from azure.storage.blob import BlobBlock
import os.path
import mimetypes
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from azure.storage import CloudStorageAccount
from storages.utils import setting
from tempfile import SpooledTemporaryFile
from django.core.files.base import File
from django.utils.encoding import force_bytes

from azure.common import AzureMissingResourceHttpError
from azure.storage.blob import ContentSettings
import base64
from django.utils.six.moves import urllib


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
        if 'w' in self._mode:
            self._storage.connection._put_blob(self._storage.azure_container, self._name, None)
        self._write_counter = 0
        self._block_list = list()
        self._last_commit_pos = 0

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
        ret = super(AzureStorageFile, self).write(force_bytes(content))
        if self._needs_flush():
            self._flush_all_buffers()
        return ret

    def _needs_flush(self, current_pos=None):
        if not(current_pos):
            current_pos = self.file.tell()
        buffer_size = current_pos - self._last_commit_pos
        ret_val = buffer_size >= self._storage.buffer_size
        return ret_val

    def _flush_buffer(self):
        self._write_counter += 1
        block_id = force_bytes(pad_left("{}{}".format(self._name, self._write_counter), 32), 'utf-8')
        block_id = base64.urlsafe_b64encode(block_id)
        block_id = urllib.parse.quote_plus(block_id)
        self.file.seek(self._last_commit_pos)
        content = self.file.read(self._storage.buffer_size)
        self._storage.connection.put_block(self._storage.azure_container, self._name,
                                           content, block_id)
        self._block_list.append(BlobBlock(block_id))
        self._last_commit_pos = self.file.tell()

    def _flush_all_buffers(self):
        """
        Flushes the write buffer.
        """
        pos_before_flush = self.file.tell()
        while self._needs_flush(pos_before_flush):
            self._flush_buffer()
        self.file.seek(pos_before_flush)

    def close(self):
        if self._is_dirty:
            self._flush_buffer()
            self._storage.connection.put_block_list(self._storage.azure_container, self._name, self._block_list)
        if self._file is not None:
            self._file.close()
            self._file = None


@deconstructible
class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    max_memory_size = setting('AZURE_BLOB_MAX_MEMORY_SIZE', 0)
    buffer_size = setting('AZURE_FILE_BUFFER_SIZE', 4194304)

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
        modified = properties.last_modified
        return modified
