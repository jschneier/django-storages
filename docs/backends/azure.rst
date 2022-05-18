Azure Storage
=============

A custom storage system for Django using Windows Azure Storage backend.


Notes
*****

Be aware Azure file names have some extra restrictions. They can't:

  - end with a dot (``.``) or slash (``/``)
  - contain more than 256 slashes (``/``)
  - be longer than 1024 characters

This is usually not an issue, since some file-systems won't
allow this anyway.
There's ``default_storage.get_name_max_len()`` method
to get the ``max_length`` allowed. This is useful
for form inputs. It usually returns
``1024 - len(azure_location_setting)``.
There's ``default_storage.get_valid_name(...)`` method
to clean up file names when migrating to Azure.

Gzipping for static files must be done through Azure CDN.


Install
*******

Install Azure SDK::

  pip install django-storages[azure]


Private VS Public Access
************************

The ``AzureStorage`` allows a single container. The container may have either
public access or private access. When dealing with a private container, the
``AZURE_URL_EXPIRATION_SECS`` must be set to get temporary URLs.

A common setup is having private media files and public static files,
since public files allow for better caching (i.e: no query-string within the URL).

One way to support this is having two backends, a regular ``AzureStorage``
with the private container and expiration setting set, and a custom
backend (i.e: a subclass of ``AzureStorage``) for the public container.

Custom backend::

    # file: ./custom_storage/custom_azure.py
    class PublicAzureStorage(AzureStorage):
        account_name = 'myaccount'
        account_key = 'mykey'
        azure_container = 'mypublic_container'
        expiration_secs = None

Then on settings set::

    DEFAULT_FILE_STORAGE = 'storages.backends.azure_storage.AzureStorage'
    STATICFILES_STORAGE = 'custom_storage.custom_azure.PublicAzureStorage'

+++++++++++++++++++++
Private VS Public URL
+++++++++++++++++++++

The difference between public and private URLs is that private includes the SAS token.
With private URLs you can override certain properties stored for the blob by specifying
query parameters as part of the shared access signature. These properties include the
cache-control, content-type, content-encoding, content-language, and content-disposition.
See https://docs.microsoft.com/en-us/rest/api/storageservices/set-blob-properties#remarks

You can specify these parameters by::
    az_storage = AzureStorage()
    az_url = az_storage.url(blob_name, parameters={'content_type': 'text/html;'})


Settings
********

The following settings should be set within the standard django
configuration file, usually `settings.py`.

Set the default storage (i.e: for media files) and the static storage
(i.e: fo static files) to use the azure backend::

    DEFAULT_FILE_STORAGE = 'storages.backends.azure_storage.AzureStorage'
    STATICFILES_STORAGE = 'storages.backends.azure_storage.AzureStorage'

The following settings are available:

``AZURE_ACCOUNT_NAME``

    This setting is the Windows Azure Storage Account name, which in many cases
    is also the first part of the url for instance: http://azure_account_name.blob.core.windows.net/
    would mean::

       AZURE_ACCOUNT_NAME = "azure_account_name"

``AZURE_ACCOUNT_KEY``

    This is the private key that gives Django access to the Windows Azure Account.

``AZURE_CONTAINER``

    This is where the files uploaded through Django will be uploaded.
    The container must be already created, since the storage system will not attempt to create it.

``AZURE_SSL``

    Set a secure connection (HTTPS), otherwise it makes an insecure connection (HTTP). Default is ``True``

``AZURE_UPLOAD_MAX_CONN``

    Number of connections to make when uploading a single file. Default is ``2``

``AZURE_CONNECTION_TIMEOUT_SECS``

    Global connection timeout in seconds. Default is ``20``

``AZURE_BLOB_MAX_MEMORY_SIZE``

    Maximum memory used by a downloaded file before dumping it to disk. Unit is in bytes. Default is ``2MB``

``AZURE_URL_EXPIRATION_SECS``

    Seconds before a URL expires, set to ``None`` to never expire it.
    Be aware the container must have public read permissions in order
    to access a URL without expiration date. Default is ``None``

``AZURE_OVERWRITE_FILES``

    Overwrite an existing file when it has the same name as the file being uploaded.
    Otherwise, rename it. Default is ``False``

``AZURE_LOCATION``

    Default location for the uploaded files. This is a path that gets prepended to every file name.

``AZURE_ENDPOINT_SUFFIX``

    Defaults to ``core.windows.net``. Use ``core.chinacloudapi.cn`` for Azure.cn accounts.

``AZURE_CUSTOM_DOMAIN``

    The custom domain to use. This can be set in the Azure Portal. For
    example, ``www.mydomain.com`` or ``mycdn.azureedge.net``.

``AZURE_CONNECTION_STRING``

    If specified, this will override all other parameters.
    See http://azure.microsoft.com/en-us/documentation/articles/storage-configure-connection-string/
    for the connection string format.

``AZURE_TOKEN_CREDENTIAL``

    A token credential used to authenticate HTTPS requests. The token value
    should be updated before its expiration.


``AZURE_CACHE_CONTROL``

    A variable to set the Cache-Control HTTP response header. E.g.
    ``AZURE_CACHE_CONTROL = "public,max-age=31536000,immutable"``

``AZURE_OBJECT_PARAMETERS``

    Use this to set content settings on all objects. To set these on a per-object
    basis, subclass the backend and override ``AzureStorage.get_object_parameters``.
    
    This is a Python ``dict`` and the possible parameters are: ``content_type``, ``content_encoding``, ``content_language``, ``content_disposition``, ``cache_control``, and ``content_md5``.

``AZURE_API_VERSION``

    The api version to use. The default value is ``None``.
