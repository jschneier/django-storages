Azure Storage
=============

A custom storage system for Django using Windows Azure Storage backend.

Before you start configuration, you will need to install the Azure SDK for Python.

Install the package::

  pip install azure-storage

Add to your requirements file::

  pip freeze > requirements.txt


Settings
********

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


To allow ``django-admin.py`` collectstatic to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.azure_storage.AzureStorage'


Available are numerous settings. It should be especially noted the following:


``AZURE_QUERYSTRING_AUTH`` (optional; default is ``True``)
    Setting ``AZURE_QUERYSTRING_AUTH`` to ``False`` removes `query parameter
    authentication`_ from generated URLs. This can be useful if your S3 buckets are
    public.

``AZURE_QUERYSTRING_EXPIRE`` (optional; default is 3600 seconds)
    The number of seconds that a generated URL with `query parameter
    authentication`_ is valid for.

``AZURE_SSL`` (optional; default is ``True```) 
    Force to use HTTPS
