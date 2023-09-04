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
``default`` above inside of the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.azure_storage.AzureStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Authentication Settings
~~~~~~~~~~~~~~~~~~~~~~~

Several different methods of authentication are provided. In order of precedence they are:

#. ``connection_string`` or ``AZURE_CONNECTION_STRING`` (see `Connection string docs <http://azure.microsoft.com/en-us/documentation/articles/storage-configure-connection-string/>`_)
#. (``account_key`` or ``AZURE_ACCOUNT_KEY``) and (``account_name`` or ``AZURE_ACCOUNT_NAME``)
#. ``token_credential`` or ``AZURE_TOKEN_CREDENTIAL``
#. ``sas_token`` or ``AZURE_SAS_TOKEN``

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

``max_memory`` size ``AZURE_BLOB_MAX_MEMORY_SIZE``

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

``api_version`` or ``AZURE_API_VERSION``

  Default: ``None``

  The api version to use.


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
See https://docs.microsoft.com/en-us/rest/api/storageservices/set-blob-properties#remarks

You can specify these parameters by::

    az_storage = AzureStorage()
    az_url = az_storage.url(blob_name, parameters={'content_type': 'text/html;'})
