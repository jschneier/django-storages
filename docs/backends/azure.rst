Azure Storage
=============

A custom storage system for Django using Microsoft Azure Storage backend.


Installation
------------

Install Azure SDK::

  pip install django-storages[azure]

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to save media files to Azure on Django
>= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.azure_storage.AzureStorage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.azure_storage.AzureStorage"

To put static files on Azure via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default``) in the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.azure_storage.AzureStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Authentication Settings
~~~~~~~~~~~~~~~~~~~~~~~

Several different methods of authentication are provided. In order of precedence they are:

#. ``connection_string`` or ``AZURE_CONNECTION_STRING`` (see `Connection string docs <https://azure.microsoft.com/documentation/articles/storage-configure-connection-string/>`_)
#. (``account_key`` or ``AZURE_ACCOUNT_KEY``) and (``account_name`` or ``AZURE_ACCOUNT_NAME``)
#. ``token_credential`` or ``AZURE_TOKEN_CREDENTIAL`` with ``account_name`` or ``AZURE_ACCOUNT_NAME``
#. ``sas_token`` or ``AZURE_SAS_TOKEN``

Using Managed Identity
++++++++++++++++++++++

`Azure Managed Identity <https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview>`_ is an authentication method that allows you to authenticate to Azure services without storing credentials in your code.
Managed Identity is the recommended mechanism for password-less authentication to Azure Storage Accounts from other Azure services like App Services, Functions, Container Apps, and VMs.

To use Managed Identity you will need to configure a System Assigned Managed Identity or a User Assigned Managed Identity for your app service. Then you can use the `DefaultAzureCredential <https://learn.microsoft.com/python/api/overview/azure/identity-readme?view=azure-python#defaultazurecredential>`_ class from the Azure SDK to authenticate. 
This class will automatically try all the available authentication methods in the order of precedence. ``DefaultAzureCredential`` will also use environment variables for local development, or VS Code Azure Login if available.

This `guide <https://learn.microsoft.com/azure/storage/blobs/storage-quickstart-blobs-python?tabs=managed-identity%2Croles-azure-portal%2Csign-in-azure-cli&pivots=blob-storage-quickstart-scratch#authenticate-to-azure-and-authorize-access-to-blob-data>`_ contains more information on assigning roles to Storage Accounts.

Before using Managed Identity, you will need to install the Azure Identity package::

  pip install azure-identity

After creating the containers in the Azure Storage Account, you can configure Managed Identity in Django settings. 
Import ``DefaultAzureCredential`` from ``azure.identity`` to use it for the ``token_credential`` property::


  from azure.identity import DefaultAzureCredential

  ...

  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.azure_storage.AzureStorage",
          "OPTIONS": {
              "token_credential": DefaultAzureCredential(),
              "account_name": "mystorageaccountname",
              "azure_container": "media",
          },
      },
      "staticfiles": {
          "BACKEND": "storages.backends.azure_storage.AzureStorage",
          "OPTIONS": {
              "token_credential": DefaultAzureCredential(),
              "account_name": "mystorageaccountname",
              "azure_container": "static",
          },
      },
  }

For `User assigned Managed Identity <https://learn.microsoft.com/python/api/overview/azure/identity-readme?view=azure-python#specify-a-user-assigned-managed-identity-for-defaultazurecredential>`_, pass the client ID parameter to the DefaultAzureCredential call.

Settings
~~~~~~~~

``azure_container`` or ``AZURE_CONTAINER``

  **Required**

  This is where the files uploaded through Django will be uploaded.
  The container must be already created, since the storage system will not attempt to create it.

``azure_ssl`` or ``AZURE_SSL``

  Default: ``True``

  Set a secure connection (HTTPS), otherwise it makes an insecure connection (HTTP).

``upload_max_conn`` or ``AZURE_UPLOAD_MAX_CONN``

  Default: ``2``

  Number of connections to make when uploading a single file.

``timeout`` or ``AZURE_CONNECTION_TIMEOUT_SECS``

  Default: ``20``

  Global connection timeout in seconds.

``max_memory_size`` or ``AZURE_BLOB_MAX_MEMORY_SIZE``

  Default: ``2*1024*1024`` i.e ``2MB``

  Maximum memory used by a downloaded file before dumping it to disk in bytes.

``expiration_secs`` or ``AZURE_URL_EXPIRATION_SECS``

  Default: ``None``

  Seconds before a URL expires, set to ``None`` to never expire it.
  Be aware the container must have public read permissions in order
  to access a URL without expiration date.

``overwrite_files`` or ``AZURE_OVERWRITE_FILES``

  Default: ``False``

  Whether or not to overwrite a file previously uploaded with the same name. If not, random character are appended.

``location`` or ``AZURE_LOCATION``

  Default: ``''``

  Default location for the uploaded files. This is a path that gets prepended to every file name.

``endpoint_suffix`` or ``AZURE_ENDPOINT_SUFFIX``

  Default: ``core.windows.net``

  Use ``core.chinacloudapi.cn`` for azure.cn accounts.

``custom_domain`` or ``AZURE_CUSTOM_DOMAIN``

  Default: ``None``

  The custom domain to use for generating URLs for files. For
  example, ``www.mydomain.com`` or ``mycdn.azureedge.net``.

``AZURE_TOKEN_CREDENTIAL``

    A token credential used to authenticate HTTPS requests. The token value
    should be updated before its expiration.


``cache_control`` or ``AZURE_CACHE_CONTROL``

  Default: ``None``

  A variable to set the Cache-Control HTTP response header. E.g.::

    cache_control: "public,max-age=31536000,immutable"

``object_parameters`` or ``AZURE_OBJECT_PARAMETERS``

  Default: ``{}``

  Use this to set content settings on all objects. To set these on a per-object
  basis, subclass the backend and override ``AzureStorage.get_object_parameters``.

  This is a Python ``dict`` and the possible parameters are: ``content_type``, ``content_encoding``, ``content_language``, ``content_disposition``, ``cache_control``, and ``content_md5``.

``client_options`` or ``AZURE_CLIENT_OPTIONS``

  Default: ``{}``

  A dict of kwarg options to send to the ``BlobServiceClient``. A partial list of options can be found
  `in the client docs <https://learn.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python#keyword-only-parameters>`__.

  Additionally, this setting can be used to configure the client retry settings. To see how follow the
  `Python retry docs <https://learn.microsoft.com/en-us/azure/storage/blobs/storage-retry-policy-python>`__.

``api_version`` or ``AZURE_API_VERSION``

  Default: ``None``

  **Note: This option is deprecated. Use client_options/AZURE_CLIENT_OPTIONS instead.**

  The Azure Storage API version to use. Default value is the most recent service version that is compatible with the current SDK.
  Setting to an older version may result in reduced feature compatibility.

Using with Azurite (previously Azure Storage Emulator)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Azurite is a local emulator for Azure Storage accounts that emulates the API for Azure Blob storage and enables local testing and development without an Azure account, free of charge.

To use the Azure Storage Emulator, you download and install it from the `Azurite page <https://learn.microsoft.com/azure/storage/common/storage-use-azurite>`_.

Copy the default `connection string <https://learn.microsoft.com/azure/storage/common/storage-use-azurite?tabs=visual-studio-code%2Cblob-storage#http-connection-strings>`_ and set it in your settings::

  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.azure_storage.AzureStorage",
          "OPTIONS": {
              "connection_string": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;",
              "azure_container": "media",
          },
      },
      "staticfiles": {
          "BACKEND": "storages.backends.azure_storage.AzureStorage",
          "OPTIONS": {
              "connection_string": "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;",
              "azure_container": "static",
          },
      },
  }

Django Storages will not create containers if they don't exist, so you will need to create any storage containers using the Azurite CLI or the Azure Storage Explorer.

Additional Notes
----------------

Filename Restrictions
~~~~~~~~~~~~~~~~~~~~~

Azure file names have some extra restrictions. They can't:

- end with a dot (``.``) or slash (``/``)
- contain more than 256 slashes (``/``)
- be longer than 1024 characters

Private vs Public URLs
~~~~~~~~~~~~~~~~~~~~~~

The difference between public and private URLs is that private includes the SAS token.
With private URLs you can override certain properties stored for the blob by specifying
query parameters as part of the shared access signature. These properties include the
cache-control, content-type, content-encoding, content-language, and content-disposition.
See https://docs.microsoft.com/rest/api/storageservices/set-blob-properties#remarks

You can specify these parameters by::

    az_storage = AzureStorage()
    az_url = az_storage.url(blob_name, parameters={'content_type': 'text/html;'})
