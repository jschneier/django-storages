from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured

try:
    from django.utils.deconstruct import deconstructible
except ImportError:
    # Support for django 1.7 and below
    def deconstructible(func):
        return func

try:
    import azure
    from azure.storage.blob import BlockBlobService
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")

from storages.utils import setting


class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    sas_token = setting("AZURE_SAS_TOKEN")
    azure_container = setting("AZURE_CONTAINER")

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            self._connection = BlockBlobService(
                account_name=self.account_name,
                sas_token=self.sas_token)
        return self._connection

    def _open(self, name, mode="rb"):
        content = self.connection.get_blob_to_bytes(self.azure_container, name)
        return ContentFile(content)

    def exists(self, name):
        try:
            self.connection.get_blob_properties(
                self.azure_container, name)
        except azure.common.AzureMissingResourceHttpError:
            return False
        else:
            return True

    def url(self, name):
        blob_url_args = {
            'azure_container': self.azure_container,
            'blob_name': name,
        }

        return self.connection.make_blob_url(
            **blob_url_args
        )+'?'+self.sas_token

    def delete(self, name):
        try:
            self.connection.delete_blob(self.azure_container, name)
        except azure.common.AzureMissingResourceHttpError:
            pass

    def size(self, name):
        properties = self.connection.get_blob_properties(
            self.azure_container, name)
        return properties["content-length"]

    def _save(self, name, content):
        self.connection.create_blob_from_stream(self.azure_container, name, content)
        return name
