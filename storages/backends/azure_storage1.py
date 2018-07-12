import mimetypes
import os.path

from azure.common import AzureMissingResourceHttpError
from azure.storage.blob import BlockBlobService, ContentSettings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

from storages.utils import setting

try:
    import azure  # noqa
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")


def clean_name(name):
    return os.path.normpath(name).replace("\\", "/")


@deconstructible
class AzureStorage(Storage):
    """
    Azure Storage

    To be used with Azure > 1.0 library.

    https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blockblobservice.blockblobservice?view=azure-python
    """

    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")

    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None

    @property
    def connection(self):
        """
        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blockblobservice.blockblobservice?view=azure-python

        :rtype: BlockBlobService
        """
        if self._connection is None:
            self._connection = BlockBlobService(
                self.account_name, self.account_key)
        return self._connection

    @property
    def azure_protocol(self):
        """
        :return: http | https | None
        :rtype: str | None
        """
        if self.azure_ssl:
            return 'https'
        return 'http' if self.azure_ssl is not None else None

    def __get_blob_properties(self, name):
        """
        :param name: Filename
        :rtype: azure.storage.blob.models.Blob | None
        """
        try:
            return self.connection.get_blob_properties(
                self.azure_container,
                name
            )
        except AzureMissingResourceHttpError:
            return None

    def _open(self, name, mode="rb"):
        """
        :param str name: Filename
        :param str mode:
        :rtype: ContentFile
        """
        contents = self.connection.get_blob_to_bytes(self.azure_container, name)
        return ContentFile(contents.content)

    def exists(self, name):
        """
        :param name: File name
        :rtype: bool
        """
        return self.__get_blob_properties(name) is not None

    def delete(self, name):
        """
        :param name: File name
        :return: None
        """
        try:
            self.connection.delete_blob(self.azure_container, name)
        except AzureMissingResourceHttpError:
            pass

    def size(self, name):
        """
        :param name:
        :rtype: int
        """
        blob = self.connection.get_blob_properties(
            self.azure_container, name)
        return blob.properties.content_length

    def _save(self, name, content):
        """
        :param name:
        :param File content:
        :return:
        """
        if hasattr(content.file, 'content_type'):
            content_type = content.file.content_type
        else:
            content_type = mimetypes.guess_type(name)[0]

        if hasattr(content, 'chunks'):
            content_data = b''.join(chunk for chunk in content.chunks())
        else:
            content_data = content.read()

        self.connection.create_blob_from_bytes(self.azure_container, name, content_data,
                                               content_settings=ContentSettings(content_type=content_type))
        return name

    def url(self, name):
        """
        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.baseblobservice.baseblobservice?view=azure-python#make-blob-url

        :param str name: Filename
        :return: path
        """
        return self.connection.make_blob_url(
            container_name=self.azure_container,
            blob_name=name,
            protocol=self.azure_protocol,
        )

    def modified_time(self, name):
        """
        :param name:
        :rtype: datetime.datetime
        """
        blob = self.__get_blob_properties(name)

        return blob.properties.last_modified
