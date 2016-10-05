Azure Storage
===========

A custom storage system for Django using Windows Azure Storage backend.


Settings
*******

``DEFAULT_FILE_STORAGE``

This setting sets the path to the Azure storage class::

    DEFAULT_FILE_STORAGE = 'storages.backends.azure_storage.AzureStorage'

To use azure_storage>=0.33, this setting will be::

    DEFAULT_FILE_STORAGE = 'storages.backends.azure_storage03.AzureStorage'


``AZURE_ACCOUNT_NAME``

This setting is the Windows Azure Storage Account name, which in many cases is also the first part of the url for instance: http://azure_account_name.blob.core.windows.net/ would mean::

   AZURE_ACCOUNT_NAME = "azure_account_name"

``AZURE_ACCOUNT_KEY``

This is the private key that gives your Django app access to your Windows Azure Account.

``AZURE_SAS_TOKEN``

In case of azure_storage>=0.33, instad of `AZURE_ACCOUNT_KEY` `SAS_TOKEN` is the private key that gives your Django app access to your Windows Azure Account.

``AZURE_CONTAINER``

This is where the files uploaded through your Django app will be uploaded.
The container must be already created as the storage system will not attempt to create it.
