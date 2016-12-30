Azure Storage
===========

A custom storage system for Django using Windows Azure Storage backend.

Before you start configuration, you will need to install the Azure SDK for Python.

Install the package::

  pip install azure

Add to your requirements file::

  pip freeze > requirements.txt


Settings
*******

To use `AzureStorage` set::

    DEFAULT_FILE_STORAGE = 'storages.backends.azure_storage.AzureStorage'

The following settings are available:

``AZURE_ACCOUNT_NAME``

    This setting is the Windows Azure Storage Account name, which in many cases is also the first part of the url for instance: http://azure_account_name.blob.core.windows.net/ would mean::

       AZURE_ACCOUNT_NAME = "azure_account_name"

``AZURE_ACCOUNT_KEY``

    This is the private key that gives your Django app access to your Windows Azure Account.

``AZURE_CONTAINER``

    This is where the files uploaded through your Django app will be uploaded.
    The container must be already created as the storage system will not attempt to create it.
