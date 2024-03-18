SFTP
====

Installation
------------

Install via::

  pip install django-storages[sftp]

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to save media files to SFTP on Django
>= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.sftpstorage.SFTPStorage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.sftpstorage.SFTPStorage"

To put static files on SFTP via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default``) in the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.sftpstorage.SFTPStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Settings
~~~~~~~~

``host`` or ``SFTP_STORAGE_HOST``

  **Required**

  The hostname where you want the files to be saved.

``root_path`` or ``SFTP_STORAGE_ROOT``

  Default: ``''``

  The root directory on the remote host into which files should be placed.
  Should work the same way that ``STATIC_ROOT`` works for local files. Must
  include a trailing slash.

``params`` or ``SFTP_STORAGE_PARAMS``

  Default: ``{}``

  A dictionary containing connection parameters to be passed as keyword
  arguments to ``paramiko.SSHClient().connect()`` (do not include hostname here).
  See `paramiko SSHClient.connect() documentation`_ for details

``interactive`` or ``SFTP_STORAGE_INTERACTIVE``

  Default: ``False``

  A boolean indicating whether to prompt for a password if the connection cannot
  be made using keys, and there is not already a password in
  ``params``. You can set this to ``True`` to enable interactive
  login when running ``manage.py collectstatic``, for example.

  .. warning::

    DO NOT set ``interactive`` to ``True`` if you are using this storage
    for files being uploaded to your site by users, because you'll have no way
    to enter the password when they submit the form

``file_mode`` or ``SFTP_STORAGE_FILE_MODE``

  Default: ``None``

  A bitmask for setting permissions on newly-created files. See
  `Python os.chmod documentation`_ for acceptable values.

``dir_mode`` or ``SFTP_STORAGE_DIR_MODE``

  Default: ``None``

  A bitmask for setting permissions on newly-created directories. See
  `Python os.chmod documentation`_ for acceptable values.

  .. note::

    Hint: if you start the mode number with a 0 you can express it in octal
    just like you would when doing "chmod 775 myfile" from bash.

``uid`` or ``SFTP_STORAGE_UID``

  Default: ``None``

  UID of the account that should be set as the owner of the files on the remote
  host. You may have to be root to set this.

``gid`` or ``SFTP_STORAGE_GID``

  Default: ``None``

  GID of the group that should be set on the files on the remote host. You have
  to be a member of the group to set this.

``known_host_file`` or ``SFTP_KNOWN_HOST_FILE``

  Default: ``None``

  Absolute path of know host file, if it isn't set ``"~/.ssh/known_hosts"`` will be used.

``base_url`` or ``SFTP_BASE_URL``

  Default: Django ``MEDIA_URL`` setting

  The URL to serve files from.

.. _`paramiko SSHClient.connect() documentation`: http://docs.paramiko.org/en/latest/api/client.html#paramiko.client.SSHClient.connect

.. _`Python os.chmod documentation`: http://docs.python.org/library/os.html#os.chmod


Standalone Use
--------------

If you intend to construct a storage instance not through Django but directly,
use the storage instance as a context manager to make sure the underlying SSH
connection is closed after use and no longer consumes resources.

.. code-block:: python

    from storages.backends.sftpstorage import SFTPStorage

    with SFTPStorage(...) as sftp:
        sftp.listdir("")
