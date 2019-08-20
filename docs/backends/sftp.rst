SFTP
====

Settings
--------

``SFTP_STORAGE_HOST``
    The hostname where you want the files to be saved.

``SFTP_STORAGE_ROOT``
    The root directory on the remote host into which files should be placed.
    Should work the same way that ``STATIC_ROOT`` works for local files. Must
    include a trailing slash.

``SFTP_STORAGE_PARAMS`` (optional)
    A dictionary containing connection parameters to be passed as keyword
    arguments to ``paramiko.SSHClient().connect()`` (do not include hostname here).
    See `paramiko SSHClient.connect() documentation`_ for details

``SFTP_STORAGE_INTERACTIVE`` (optional)
    A boolean indicating whether to prompt for a password if the connection cannot
    be made using keys, and there is not already a password in
    ``SFTP_STORAGE_PARAMS``. You can set this to ``True`` to enable interactive
    login when running ``manage.py collectstatic``, for example.

    .. warning::

      DO NOT set SFTP_STORAGE_INTERACTIVE to True if you are using this storage
      for files being uploaded to your site by users, because you'll have no way
      to enter the password when they submit the form..

``SFTP_STORAGE_FILE_MODE`` (optional)
    A bitmask for setting permissions on newly-created files. See
    `Python os.chmod documentation`_ for acceptable values.

``SFTP_STORAGE_DIR_MODE`` (optional)
    A bitmask for setting permissions on newly-created directories. See
    `Python os.chmod documentation`_ for acceptable values.

    .. note::

      Hint: if you start the mode number with a 0 you can express it in octal
      just like you would when doing "chmod 775 myfile" from bash.

``SFTP_STORAGE_UID`` (optional)
    UID of the account that should be set as the owner of the files on the remote
    host. You may have to be root to set this.

``SFTP_STORAGE_GID`` (optional)
    GID of the group that should be set on the files on the remote host. You have
    to be a member of the group to set this.

``SFTP_KNOWN_HOST_FILE`` (optional)
    Absolute path of know host file, if it isn't set ``"~/.ssh/known_hosts"`` will be used.


.. _`paramiko SSHClient.connect() documentation`: http://docs.paramiko.org/en/latest/api/client.html#paramiko.client.SSHClient.connect

.. _`Python os.chmod documentation`: http://docs.python.org/library/os.html#os.chmod
