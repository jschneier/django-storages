import mimetypes
import os.path
import posixpath
import time
from datetime import datetime
from time import mktime

from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

from storages.utils import safe_join, setting

try:
    import azure  # noqa
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")

if (setting("AZURE_2018_SDK")):
    from azure.storage.blob import BlockBlobService, ContentSettings
    from azure.common import AzureMissingResourceHttpError
else:
    try:
        # azure-storage 0.20.0
        from azure.storage.blob.blobservice import BlobService
        from azure.common import AzureMissingResourceHttpError
    except ImportError:
        from azure.storage import BlobService
        from azure import WindowsAzureMissingResourceError as AzureMissingResourceHttpError


@deconstructible
class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    azure_location = setting("AZURE_LOCATION", "")

    def __init__(self, *args, **kwargs):
        super(AzureStorage, self).__init__(*args, **kwargs)
        self._connection = None
        self.azure_location = (self.azure_location or '').lstrip('/')

    @property
    def connection(self):
        if self._connection is None:
            if (setting("AZURE_2018_SDK")):
                self._connection = BlockBlobService(account_name=self.account_name, account_key=self.account_key)
            else:
                self._connection = BlobService(self.account_name, self.account_key)
        return self._connection

    @property
    def azure_protocol(self):
        if self.azure_ssl:
            return 'https'
        return 'http' if self.azure_ssl is not None else None

    def _open(self, name, mode="rb"):
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
        properties = self.connection.get_blob_properties(
            self.azure_container, name)
        return properties["content-length"]

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

        if (setting("AZURE_2018_SDK")):
            self.connection.create_blob_from_bytes(self.azure_container, name,
                                 content_data, content_settings=ContentSettings(content_type=content_type))
        else:
            self.connection.put_blob(self.azure_container, name,
                                 content_data, "BlockBlob", x_ms_blob_content_type=content_type)

        return name

    def url(self, name):
        name = self._normalize_name(self._clean_name(name))
        if hasattr(self.connection, 'make_blob_url'):
            return self.connection.make_blob_url(
                container_name=self.azure_container,
                blob_name=name,
                protocol=self.azure_protocol,
            )
        else:
            return "{}{}/{}".format(setting('MEDIA_URL'), self.azure_container, name)

    def get_modified_time(self, name):
        name = self._normalize_name(self._clean_name(name))
        try:
            prop = self.connection.get_blob_properties(self.azure_container, name)
            modified = prop.properties.last_modified
        except (TypeError, KeyError):
            return super(AzureStorage, self).modified_time(name)

        return modified

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
