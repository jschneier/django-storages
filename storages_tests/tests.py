"""
=================
Django S3 storage
=================

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
