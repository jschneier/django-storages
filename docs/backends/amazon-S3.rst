Amazon S3
=========

Usage
*****

There are two backend APIs for interacting with S3. The first is the s3 backend (in storages/backends/s3.py) which is simple and based on the Amazon S3 Python library. The second is the s3boto backend (in storages/backends/s3boto.py) which is well-maintained by the community and is generally more robust (including connection pooling, etc...). s3boto requires the python-boto library.

Settings
--------

``DEFAULT_FILE_STORAGE``

This setting sets the path to the S3 storage class, the first part correspond to the filepath and the second the name of the class, if you've got example.com in your PYTHONPATH and store your storage file in example.com/libs/storages/S3Storage.py, the resulting setting will be::

    DEFAULT_FILE_STORAGE = 'libs.storages.S3Storage.S3Storage'

or if you installed using setup.py::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3.S3Storage'

If you keep the same filename as in repository, it should always end with S3Storage.S3Storage.

To use s3boto, this setting will be::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto.S3BotoStorage'

``AWS_ACCESS_KEY_ID``

Your Amazon Web Services access key, as a string.

``AWS_SECRET_ACCESS_KEY``

Your Amazon Web Services secret access key, as a string.

``AWS_STORAGE_BUCKET_NAME``

Your Amazon Web Services storage bucket name, as a string.

``AWS_CALLING_FORMAT`` (Subdomain hardcoded in s3boto)

The way you'd like to call the Amazon Web Services API, for instance if you prefer subdomains::

    from S3 import CallingFormat
    AWS_CALLING_FORMAT = CallingFormat.SUBDOMAIN

``AWS_HEADERS`` (optional)

If you'd like to set headers sent with each file of the storage::

    # see http://developer.yahoo.com/performance/rules.html#expires
    AWS_HEADERS = {
        'Expires': 'Thu, 15 Apr 2010 20:00:00 GMT',
        'Cache-Control': 'max-age=86400',
    }

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
