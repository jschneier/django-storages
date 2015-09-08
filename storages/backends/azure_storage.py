import os.path
import mimetypes

from django.core.files.base import ContentFile
from django.core.exceptions import ImproperlyConfigured
from storages.compat import Storage

try:
    import azure
    from azure.storage.blob.blobservice import BlobService
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")

from storages.utils import setting


def clean_name(name):
    return os.path.normpath(name).replace("\\", "/")


class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    azure_protocol = 'https:' if azure_ssl else 'http:' if azure_ssl is not None else ''

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            self._connection = BlobService(
                self.account_name, self.account_key)
        return self._connection

    def _open(self, name, mode="rb"):
        contents = self.connection.get_blob(self.azure_container, name)
        return ContentFile(contents)

    def exists(self, name):
        try:
            self.connection.get_blob_properties(
                self.azure_container, name)
        except azure.common.AzureMissingResourceHttpError:
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
        (content_type, encoding) = mimetypes.guess_type(name)
        self.connection.put_blob(
            container_name=self.azure_container,
            blob_name=name,
            blob=content.read(),
            x_ms_blob_type="BlockBlob",
            x_ms_blob_content_type=content_type,
            x_ms_blob_content_encoding=encoding,
        )
        return name

    def url(self, name):
        protocol = 'https:' if self.azure_ssl else 'http:' if self.azure_ssl is not None else None
        return self.connection.make_blob_url(
            container_name=self.azure_container,
            blob_name=name,
            protocol=protocol,
        )
