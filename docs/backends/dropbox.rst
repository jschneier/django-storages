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

``DROPBOX_ROOT_PATH`` (optional, default ``'/'``)
   Path which will prefix all uploaded files. Must begin with a ``/``.

``DROPBOX_TIMEOUT`` (optional, default ``100``)
   Timeout in seconds for requests to the API. If ``None``, the client will wait forever.
   The default value matches the SDK at the time of this writing.

``DROPBOX_WRITE_MODE`` (optional, default ``'add'``)
   Sets the Dropbox WriteMode strategy. Read more in the `official docs`_.

.. _`tutorial`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`Dropbox SDK for Python`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`official docs`: https://dropbox-sdk-python.readthedocs.io/en/latest/api/files.html#dropbox.files.WriteMode
