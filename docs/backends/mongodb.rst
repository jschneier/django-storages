MongoDB
=======

A GridFS backend that works with django_mongodb_engine and the upcoming GSoC 2010 MongoDB backend which gets developed by Alex Gaynor.

Usage (in settings.py)::

    DATABASES = {
        'default': {
            'ENGINE': 'django_mongodb_engine.mongodb',
            'NAME': 'test',
            'USER': '',
            'PASSWORD': '',
            'HOST': 'localhost',
            'PORT': 27017,
            'SUPPORTS_TRANSACTIONS': False,
        }
    }

    DEFAULT_FILE_STORAGE = 'storages.backends.mongodb.GridFSStorage'
    GRIDFS_DATABASE = 'default'
