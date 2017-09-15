QingStorage
=============

A custom storage system for Django using QingStor backend.

Before you start configuration, you will need to install the QingStor SDK for Python.

Install the package::

  pip install qingstor-sdk


Settings
********

To use `QingStorStorage` set::

    DEFAULT_FILE_STORAGE = 'storages.backends.qingstor.QingStorage'

The following settings are available:

``QINGSTOR_ACCESS_KEY_ID``

    This setting is the QingStorage access key ID:
       QINGSTOR_ACCESS_KEY_ID = "access_key_id"

``QINGSTOR_SECRET_ACCESS_KEY``

    This is the private key that gives your Django app access to your QingStor access key ID:
        QINGSTOR_SECRET_ACCESS_KEY = "secret_access_key"

``QINGSTOR_BUCKET_NAME``

    This is the bucket name that you want to access to.
        QINGSTOR_BUCKET_NAME = "bucket_name"

``QINGSTOR_BUCKET_ZONE``

    This is the bucket zone which the bucket you want to access to.

``QINGSTOR_SECURE_URL``

    This is the flag which means if your protocol is "https", which means `True` is "https" and `False` is "http".
    The default value is `True`.
