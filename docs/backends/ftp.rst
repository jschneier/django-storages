FTP
===

.. warning:: This FTP storage is not prepared to work with large files, because it uses memory for temporary data storage. It also does not close FTP connection automatically (but open it lazy and try to reestablish when disconnected).

This implementation was done preliminary for upload files in admin to remote FTP location and read them back on site by HTTP. It was tested mostly in this configuration, so read/write using FTPStorageFile class may break.

Settings
--------

To use FtpStorage set::

    DEFAULT_FILE_STORAGE = 'storages.backends.ftp.FTPStorage'

``FTP_STORAGE_LOCATION``
    URL of the server that holds the files. Example ``'ftp://<user>:<pass>@<host>:<port>'``

``BASE_URL``
    URL that serves the files stored at this location. Defaults to the value of your ``MEDIA_URL`` setting.

Optional parameters
~~~~~~~~~~~~~~~~~~~

``ENCODING``
    File encoding. Example ``'utf-8'``. Default value ``'latin-1'``
