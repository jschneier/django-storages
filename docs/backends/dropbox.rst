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

Two methods of authenticating are supported: 1) using an access token, or 2) using a refresh token with an app key and
secret. Dropbox has recently introduced short-lived access tokens only, and does not seem to allow new apps to generate
access tokens that do not expire. Short-lived access tokens can be indentified by their prefix. (i.e., short-lived
access tokens start with ``'sl.'``). Please set the following variables accordingly:

``DROPBOX_OAUTH2_TOKEN``
   Your Dropbox access token. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_OAUTH2_REFRESH_TOKEN``
   Your Dropbox refresh token. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_APP_KEY``
   Your Dropbox application key. Necessary to refresh the token. Set this variable in case you can only generate
   short-lived tokens.

``DROPBOX_APP_SECRET``
   Your Dropbox application secret. Necessary to refresh the token. Set this variable in case you can only generate
   short-lived tokens.

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
