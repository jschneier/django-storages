Dropbox
=======

A Django files storage using Dropbox as a backend via the official
`Dropbox SDK for Python`_. Currently only v2 of the API is supported.

Before you start configuration, you will need to install the SDK
which can be done for you automatically by doing::

   pip install django-storages[dropbox]

Settings
--------

To use DropBoxStorage set::

    DEFAULT_FILE_STORAGE = 'storages.backends.dropbox.DropBoxStorage'

``DROPBOX_OAUTH2_TOKEN``
    Your Dropbox token. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_ROOT_PATH`` (optional)
    Allow to jail your storage to a defined directory.

``DROPBOX_TIMEOUT`` (optional)
      Timeout in seconds for making requests to the API. If ``None``, the client will wait forever.
      The default is ``100`` seconds which is the current default in the official SDK.

.. _`tutorial`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`Dropbox SDK for Python`: https://www.dropbox.com/developers/documentation/python#tutorial
