Dropbox
=======

A Django files storage using Dropbox as a backend via the official
`Dropbox SDK for Python`_. Currently only v2 of the API is supported.

Installation
------------

Before you start configuration, you will need to install the SDK
which can be done for you automatically by doing::

   pip install django-storages[dropbox]

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to save media files to Dropbox on Django
>= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.dropbox.DropboxStorage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.dropbox.DropboxStorage"

To put static files on Dropbox via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default``) in the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.dropbox.DropboxStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Authentication
--------------

Two methods of authentication are supported:

#. Using an access token
#. Using a refresh token with an app key and secret

Dropbox has recently introduced short-lived access tokens only, and does not seem to allow new apps to generate access tokens that do not expire. Short-lived access tokens can be indentified by their prefix (short-lived access tokens start with ``'sl.'``).

You can manually obtain the refresh token by following the instructions below using ``APP_KEY`` and ``APP_SECRET``.

The relevant settings which can all be obtained by following the instructions in the `tutorial`_:

#. ``oauth2_access_token`` or ``DROPBOX_OAUTH2_TOKEN``
#. ``oauth2_refresh_token`` or ``DROPBOX_OAUTH2_REFRESH_TOKEN``
#. ``app_secret`` or ``DROPBOX_APP_SECRET``
#. ``app_key`` or ``DROPBOX_APP_KEY``

The refresh token can be obtained using the `commandline-oauth.py`_ example from the `Dropbox SDK for Python`_.

Get AUTHORIZATION_CODE
~~~~~~~~~~~~~~~~~~~~~~

Using your ``APP_KEY`` follow the link:

   https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&token_access_type=offline&response_type=code

It will give you ``AUTHORIZATION_CODE``.

Obtain the refresh token
~~~~~~~~~~~~~~~~~~~~~~~~

Usinh your ``APP_KEY``, ``APP_SECRET`` and ``AUTHORIZATION_KEY`` obtain the refresh token.

.. code-block:: shell

   curl -u APP_KEY:APP_SECRET \
   -d "code=AUTHORIZATION_CODE&grant_type=authorization_code" \
   -H "Content-Type: application/x-www-form-urlencoded" \
   -X POST "https://api.dropboxapi.com/oauth2/token"

The response would be:

.. code-block:: json

   {
      "access_token": "sl.************************",
      "token_type": "bearer",
      "expires_in": 14400,
      "refresh_token": "************************", <-- your REFRESH_TOKEN
      "scope": <SCOPES>,
      "uid": "************************",
      "account_id": "dbid:************************"
   }

Settings
--------

``root_path`` or ``DROPBOX_ROOT_PATH``

  Default: ``'/'``

  Path which will prefix all uploaded files. Must begin with a ``/``.

``timeout`` or ``DROPBOX_TIMEOUT``

  Default: ``100``

  Timeout in seconds for requests to the API. If ``None``, the client will wait forever.
  The default value matches the SDK at the time of this writing.

``write_mode`` or ``DROPBOX_WRITE_MODE``

  Default: ``'add'``

  Sets the Dropbox WriteMode strategy. Read more in the `official docs`_.


.. _`tutorial`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`Dropbox SDK for Python`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`official docs`: https://dropbox-sdk-python.readthedocs.io/en/latest/api/files.html#dropbox.files.WriteMode
.. _`commandline-oauth.py`: https://github.com/dropbox/dropbox-sdk-python/blob/master/example/oauth/commandline-oauth.py
