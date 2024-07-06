FTP
===

.. warning:: This FTP storage is not prepared to work with large files, because it uses memory for temporary data storage. It also does not close FTP connection automatically (but open it lazy and try to reestablish when disconnected).

This implementation was done preliminary for upload files in admin to remote FTP location and read them back on site by HTTP. It was tested mostly in this configuration, so read/write using FTPStorageFile class may break.

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to use FTP to save media files on
Django >= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.ftp.FTPStorage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.ftp.FTPStorage"

To use FTP to store static files via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default``) in the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.ftp.FTPStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Settings
~~~~~~~~

``location`` or ``FTP_STORAGE_LOCATION``

  **Required**

  Format as a url like ``"{scheme}://{user}:{passwd}@{host}:{port}/"``. Supports both FTP and FTPS connections via scheme.

``allow_overwrite`` or ``FTP_ALLOW_OVERWRITE``

  default: ``False``

  Set to ``True`` to overwrite files instead of appending additional characters.

``encoding`` or ``FTP_STORAGE_ENCODING``

  default: ``latin-1``

  File encoding.

``base_url`` or ``BASE_URL``

  default: ``settings.MEDIA_URL``

  Serving base of files.
