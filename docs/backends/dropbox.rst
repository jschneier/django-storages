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

Two methods of authenticating are supported:

1. using an access token
2. using a refresh token with an app key and secret

Dropbox has recently introduced short-lived access tokens only, and does not seem to allow new apps to generate access tokens that do not expire. Short-lived access tokens can be indentified by their prefix (short-lived access tokens start with ``'sl.'``).

Please set the following variables accordingly:

``DROPBOX_OAUTH2_TOKEN``
   Your Dropbox token. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_APP_KEY``
   Your Dropbox appkey. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_APP_SECRET``
   Your Dropbox secret. You can obtain one by following the instructions in the `tutorial`_.

``DROPBOX_OAUTH2_REFRESH_TOKEN``
   Your Dropbox refresh token. You can obtain one by following the instructions in the `tutorial`_.

The refresh token can be obtained using the `commandline-oauth.py`_ example from the `Dropbox SDK for Python`_.

``DROPBOX_ROOT_PATH`` (optional, default ``'/'``)
   Path which will prefix all uploaded files. Must begin with a ``/``.

``DROPBOX_TIMEOUT`` (optional, default ``100``)
   Timeout in seconds for requests to the API. If ``None``, the client will wait forever.
   The default value matches the SDK at the time of this writing.

``DROPBOX_WRITE_MODE`` (optional, default ``'add'``)
   Sets the Dropbox WriteMode strategy. Read more in the `official docs`_.

Obtain the refresh token manually
#################################

You can obtail the refresh token manually via ``APP_KEY`` and ``APP_SECRET``.

Get AUTHORIZATION_CODE
**********************

Using your ``APP_KEY`` follow the link:

   https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&token_access_type=offline&response_type=code

It will give you ``AUTHORIZATION_CODE``.

Obtain the refresh token
*************************

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

.. _`tutorial`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`Dropbox SDK for Python`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`official docs`: https://dropbox-sdk-python.readthedocs.io/en/latest/api/files.html#dropbox.files.WriteMode
.. _`commandline-oauth.py`: https://github.com/dropbox/dropbox-sdk-python/blob/master/example/oauth/commandline-oauth.py
