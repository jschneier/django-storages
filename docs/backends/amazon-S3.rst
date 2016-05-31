Amazon S3
=========

Usage
*****

There is one backend for interacting with S3 based on the boto library. A legacy backend backed on the Amazon S3 Python library was removed in version 1.2.

Settings
--------

To use s3boto set::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto.S3BotoStorage'

``AWS_ACCESS_KEY_ID``

Your Amazon Web Services access key, as a string.

``AWS_SECRET_ACCESS_KEY``

Your Amazon Web Services secret access key, as a string.

``AWS_STORAGE_BUCKET_NAME``

Your Amazon Web Services storage bucket name, as a string.

``AWS_AUTO_CREATE_BUCKET`` (optional)

If set to ``True`` the bucket specified in ``AWS_STORAGE_BUCKET_NAME`` is automatically created.


``AWS_HEADERS`` (optional)

If you'd like to set headers sent with each file of the storage::

    # see http://developer.yahoo.com/performance/rules.html#expires
    AWS_HEADERS = {
        'Expires': 'Thu, 15 Apr 2010 20:00:00 GMT',
        'Cache-Control': 'max-age=86400',
    }


``AWS_EXTRA_HEADERS`` (optional)

This option allows to set additional headers for files matching special regex
For example if you want to add "Cache-Control" header for all png images add

AWS_EXTRA_HEADERS = [
  (".*png", {"Cache-Control": "max-age=86400"})
]

To allow ``django-admin.py`` collectstatic to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.s3boto.S3BotoStorage'

Fields
------

Once you're done, default_storage will be the S3 storage::

    >>> from django.core.files.storage import default_storage
    >>> print default_storage.__class__
    <class 'S3Storage.S3Storage'>

The above doesn't seem to be true for django 1.3+ instead look at::

    >>> from django.core.files.storage import default_storage
    >>> print default_storage.connection
    S3Connection:s3.amazonaws.com

This way, if you define a new FileField, it will use the S3 storage::

    >>> from django.db import models
    >>> class Resume(models.Model):
    ...     pdf = models.FileField(upload_to='pdfs')
    ...     photos = models.ImageField(upload_to='photos')
    ...
    >>> resume = Resume()
    >>> print resume.pdf.storage
    <S3Storage.S3Storage object at ...>

Tests
*****

Initialization::

    >>> from django.core.files.storage import default_storage
    >>> from django.core.files.base import ContentFile
    >>> from django.core.cache import cache
    >>> from models import MyStorage

Storage
-------

Standard file access options are available, and work as expected::

    >>> default_storage.exists('storage_test')
    False
    >>> file = default_storage.open('storage_test', 'w')
    >>> file.write('storage contents')
    >>> file.close()

    >>> default_storage.exists('storage_test')
    True
    >>> file = default_storage.open('storage_test', 'r')
    >>> file.read()
    'storage contents'
    >>> file.close()

    >>> default_storage.delete('storage_test')
    >>> default_storage.exists('storage_test')
    False

Model
-----

An object without a file has limited functionality::

    >>> obj1 = MyStorage()
    >>> obj1.normal
    <FieldFile: None>
    >>> obj1.normal.size
    Traceback (most recent call last):
    ...
    ValueError: The 'normal' attribute has no file associated with it.

Saving a file enables full functionality::

    >>> obj1.normal.save('django_test.txt', ContentFile('content'))
    >>> obj1.normal
    <FieldFile: tests/django_test.txt>
    >>> obj1.normal.size
    7
    >>> obj1.normal.read()
    'content'

Files can be read in a little at a time, if necessary::

    >>> obj1.normal.open()
    >>> obj1.normal.read(3)
    'con'
    >>> obj1.normal.read()
    'tent'
    >>> '-'.join(obj1.normal.chunks(chunk_size=2))
    'co-nt-en-t'

Save another file with the same name::

    >>> obj2 = MyStorage()
    >>> obj2.normal.save('django_test.txt', ContentFile('more content'))
    >>> obj2.normal
    <FieldFile: tests/django_test_.txt>
    >>> obj2.normal.size
    12

Push the objects into the cache to make sure they pickle properly::

    >>> cache.set('obj1', obj1)
    >>> cache.set('obj2', obj2)
    >>> cache.get('obj2').normal
    <FieldFile: tests/django_test_.txt>

Deleting an object deletes the file it uses, if there are no other objects still using that file::

    >>> obj2.delete()
    >>> obj2.normal.save('django_test.txt', ContentFile('more content'))
    >>> obj2.normal
    <FieldFile: tests/django_test_.txt>

Default values allow an object to access a single file::

    >>> obj3 = MyStorage.objects.create()
    >>> obj3.default
    <FieldFile: tests/default.txt>
    >>> obj3.default.read()
    'default content'

But it shouldn't be deleted, even if there are no more objects using it::

    >>> obj3.delete()
    >>> obj3 = MyStorage()
    >>> obj3.default.read()
    'default content'

Verify the fix for #5655, making sure the directory is only determined once::

    >>> obj4 = MyStorage()
    >>> obj4.random.save('random_file', ContentFile('random content'))
    >>> obj4.random
    <FieldFile: .../random_file>

Clean up the temporary files::

    >>> obj1.normal.delete()
    >>> obj2.normal.delete()
    >>> obj3.default.delete()
    >>> obj4.random.delete()
