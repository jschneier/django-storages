DropBox
=======

A custom storage system for Django using Dropbox Storage backend.

Before you start configuration, you will need to install `Dropbox SDK for Python`_.


Install the package::

  pip install dropbox

Settings
--------

To use DropBoxStorage set::

    DEFAULT_FILE_STORAGE = 'storages.backends.dropbox.DropBoxStorage'

``DROPBOX_OAUTH2_TOKEN``
    Your DropBox token, if you haven't follow this `guide step`_.

``DROPBOX_ROOT_PATH`` (optional)
    Allow to jail your storage to a defined directory.

    Default: ``/``

``DROPBOX_TIMEOUT`` (optional)
    Timeout in seconds. After timeout the connection will be closed. If ``None``, client will wait forever. 

    Dropbox default: ``30`` seconds

.. _`guide step`: https://www.dropbox.com/developers/documentation/python#tutorial
.. _`Dropbox SDK for Python`: https://www.dropbox.com/developers/documentation/python#tutorial
