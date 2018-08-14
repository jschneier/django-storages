import mimetypes
import posixpath

from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

from storages.utils import safe_join, setting

try:
    from azure.storage.blob import BlockBlobService, ContentSettings
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")


@deconstructible
class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    azure_location = setting("AZURE_LOCATION", "")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._connection = None
        self.azure_location = (self.azure_location or '').lstrip('/')

    @property
    def connection(self):
        if self._connection is None:
            self._connection = BlockBlobService(account_name=self.account_name, account_key=self.account_key)
        return self._connection

    @property
    def azure_protocol(self):
        if self.azure_ssl:
            return 'https'
        return 'http' if self.azure_ssl is not None else None

    def _open(self, name, mode=None):
        name = self._normalize_name(self._clean_name(name))
        contents = self.connection.get_blob_to_bytes(self.azure_container, name).content
        return ContentFile(contents)

    def exists(self, name):
        name = self._normalize_name(self._clean_name(name))
        return self.connection.exists(self.azure_container, name)

    def delete(self, name):
        name = self._normalize_name(self._clean_name(name))
        return self.connection.delete_blob(self.azure_container, name)

    def size(self, name):
        name = self._normalize_name(self._clean_name(name))
        properties = self.connection.get_blob_properties(self.azure_container, name).properties
        return properties.content_length

    def _save(self, name, content):
        name = self._normalize_name(self._clean_name(name))
        if hasattr(content.file, 'content_type'):
            content_type = content.file.content_type
        else:
            content_type = mimetypes.guess_type(name)[0]

        if hasattr(content, 'chunks'):
            content_data = b''.join(chunk for chunk in content.chunks())
        else:
            content_data = content.read()

        self.connection.create_blob_from_bytes(
            self.azure_container,
            name,
            content_data,
            content_settings=ContentSettings(content_type=content_type)
        )

        return name

    def url(self, name):
        name = self._normalize_name(self._clean_name(name))
        return self.connection.make_blob_url(self.azure_container, name, protocol=self.azure_protocol)

    def get_modified_time(self, name):
        name = self._normalize_name(self._clean_name(name))
        properties = self.connection.get_blob_properties(self.azure_container, name).properties
        return properties.last_modified

    def _clean_name(self, name):
        """
        Cleans the name so that Windows style paths work

        (Copied from /storages/backends/s3boto3.py)
        """
        # Normalize Windows style paths
        clean_name = posixpath.normpath(name).replace('\\', '/')

        # os.path.normpath() can strip trailing slashes so we implement
        # a workaround here.
        if name.endswith('/') and not clean_name.endswith('/'):
            # Add a trailing slash as it was stripped.
            clean_name += '/'
        return clean_name

    def _normalize_name(self, name):
        """
        Normalizes the name so that paths like /path/to/ignored/../something.txt
        work. We check to make sure that the path pointed to is not outside
        the directory specified by the LOCATION setting.

        (Copied from /storages/backends/s3boto3.py)
        """
        try:
            return safe_join(self.azure_location, name)
        except ValueError:
            raise SuspiciousOperation("Attempted access to '%s' denied." %
                                      name)
