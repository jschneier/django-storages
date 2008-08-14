"""
=================
Django S3 storage
=================

Usage
=====

Settings
--------

Required
~~~~~~~~

First of all you have to specify S3 access stuff::

    DEFAULT_FILE_STORAGE = 'S3Storage.S3Storage'
    AWS_ACCESS_KEY_ID = 'foo'
    AWS_SECRET_ACCESS_KEY = 'bar'
    AWS_STORAGE_BUCKET_NAME = 'baz'


Optionnal
~~~~~~~~~

And optionnally, you can set custom settings::

    from S3 import CallingFormat
    AWS_CALLING_FORMAT = CallingFormat.SUBDOMAIN
    # see http://developer.yahoo.com/performance/rules.html#expires
    AWS_HEADERS = {
        'Expires': 'Thu, 15 Apr 2010 20:00:00 GMT', 
        'Cache-Control': 'max-age=86400',
        }

Fields
------

Once you're done, ``default_storage`` will be the S3 storage::

    >>> from django.core.files.storage import default_storage
    >>> print default_storage.__class__
    <class 'S3Storage.S3Storage'>

This way, if you define a new ``FileField``, it will use the S3 storage::

    >>> from django.db import models
    >>> class MyModel(models.Model):
    ...     myfile = models.FileField(upload_to='yourpath')
    ...
    >>> mymodel = MyModel()
    >>> print mymodel.myfile.storage
    <S3Storage.S3Storage object at ...>


Tests
=====

Initialization::

    >>> from django.core.files.storage import default_storage as s3_storage

Standard file access options are available, and work as expected::

    >>> s3_storage.exists('storage_test')
    False
    >>> file = s3_storage.open('storage_test', 'w')
    >>> file.write('storage contents')
    >>> file.close()
    
    >>> s3_storage.exists('storage_test')
    True
    >>> file = s3_storage.open('storage_test', 'r')
    >>> file.read()
    'storage contents'
    >>> file.close()
    
    >>> s3_storage.delete('storage_test')
    >>> s3_storage.exists('storage_test')
    False

"""