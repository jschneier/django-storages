from datetime import datetime, timedelta
import os.path
import mimetypes
import time
from time import mktime

from django.core.files.base import ContentFile
from django.core.exceptions import ImproperlyConfigured
from storages.compat import Storage

try:
    import azure  # noqa
except ImportError:
    raise ImproperlyConfigured(
        "Could not load Azure bindings. "
        "See https://github.com/WindowsAzure/azure-sdk-for-python")

try:
    # azure-storage 0.20.0
    from azure.storage.blob.blobservice import BlobService
    from azure.common import AzureMissingResourceHttpError
    from azure.storage import AccessPolicy, SharedAccessPolicy
except ImportError:
    from azure.storage import BlobService, AccessPolicy, SharedAccessPolicy
    from azure import WindowsAzureMissingResourceError as AzureMissingResourceHttpError

from storages.utils import setting

def clean_name(name):
    return os.path.normpath(name).replace("\\", "/")


class AzureStorage(Storage):
    account_name = setting("AZURE_ACCOUNT_NAME")
    account_key = setting("AZURE_ACCOUNT_KEY")
    azure_container = setting("AZURE_CONTAINER")
    azure_ssl = setting("AZURE_SSL")
    auto_sign = setting("AZURE_AUTO_SIGN")
    azure_access_policy_permission = setting("AZURE_ACCESS_POLICY_PERMISSION", 'r')  # defaults to 'read'
    ap_expiry = setting("AZURE_ACCESS_POLICY_EXPIRY", 120)  # defaults to 120 seconds

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
        if self.azure_ssl:
            return 'https'
        return 'http' if self.azure_ssl is not None else None

    def __get_blob_properties(self, name):
        try:
            return self.connection.get_blob_properties(
                self.azure_container,
                name
            )
        except AzureMissingResourceHttpError:
            return None

    def _open(self, name, mode="rb"):
        contents = self.connection.get_blob(self.azure_container, name)
        return ContentFile(contents)

    def exists(self, name):
        return self.__get_blob_properties(name) is not None

    def delete(self, name):
        try:
            self.connection.delete_blob(self.azure_container, name)
        except AzureMissingResourceHttpError:
            pass

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
            if self.auto_sign:
                access_policy = AccessPolicy()
                access_policy.start = (datetime.utcnow() + timedelta(seconds=-120)).strftime('%Y-%m-%dT%H:%M:%SZ')
                access_policy.expiry = (datetime.utcnow() + timedelta(seconds=self.ap_expiry)).strftime('%Y-%m-%dT%H:%M:%SZ')
                access_policy.permission = self.azure_access_policy_permission
                sap = SharedAccessPolicy(access_policy)
                
                sas_token = self.connection.generate_shared_access_signature(
                    self.azure_container,
                    blob_name=name,
                    shared_access_policy=sap,
                )
            else:
                sas_token = None
            return self.connection.make_blob_url(
                container_name=self.azure_container,
                blob_name=name,
                protocol=self.azure_protocol,
                sas_token=sas_token
            )
        else:
            return "{}{}/{}".format(setting('MEDIA_URL'), self.azure_container, name)

    def modified_time(self, name):
        try:
            modified = self.__get_blob_properties(name)['last-modified']
        except (TypeError, KeyError):
            return super(AzureStorage, self).modified_time(name)

        modified = time.strptime(modified, '%a, %d %b %Y %H:%M:%S %Z')
        modified = datetime.fromtimestamp(mktime(modified))

        return modified
