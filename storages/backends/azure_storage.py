import os.path
import mimetypes

from django.core.files.base import ContentFile
from django.core.exceptions import ImproperlyConfigured
from storages.compat import Storage

try:
    import azure
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/Azure/azure-storage-python")

try:
    # azure-storage 0.20.0
    from azure.storage.blob.blobservice import BlobService
    from azure.common import AzureMissingResourceHttpError
except ImportError:
    from azure.storage import BlobService
    from azure import WindowsAzureMissingResourceError as AzureMissingResourceHttpError

from storages.utils import setting


class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            self._connection = BlobService(
                self.account_name, self.account_key)
        return self._connection

    @property
    def azure_protocol(self):
        if azure_ssl:
            protocol = 'https'
        elif azure_ssl is not None:
            protocol = 'http'
        else:
            protocol = None

        return protocol

    def _open(self, name, mode="rb"):
        contents = self.connection.get_blob(self.azure_container, name)
        return ContentFile(contents)

    def exists(self, name):
        try:
            self.connection.get_blob_properties(
                self.azure_container, name)
        except AzureMissingResourceHttpError:
            return False
        else:
            return True

    def delete(self, name):
        self.connection.delete_blob(self.azure_container, name)

    def size(self, name):
        properties = self.connection.get_blob_properties(
            self.azure_container, name)
        return properties["content-length"]

    def _save(self, name, content):
        if hasattr(content.file, 'content_type'):
            content_type = content.file.content_type
        else:
            content_type = mimetypes.guess_type(name)[0]

        if hasattr(content, 'chunks'):
            content_data = b''.join(chunk for chunk in content.chunks())
        else:
            content_data = content.read()

        self.connection.put_blob(self.azure_container, name,
                                 content_data, "BlockBlob",
                                 x_ms_blob_content_type=content_type)
        return name

    def url(self, name):
        if hasattr(self.connection, 'make_blob_url'):
            return self.connection.make_blob_url(
                container_name=self.azure_container,
                blob_name=name,
                protocol=self.azure_protocol,
            )
        else:
            return "{}{}/{}".format(setting('MEDIA_URL'), self.azure_container, name)
