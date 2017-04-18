Google Cloud Storage
====================

Usage
*****

This backend provides support for Google Cloud Storage using the
library provided by Google.

It's possible to access Google Cloud Storage in S3 compatibility mode
using other libraries in django-storages, but this is the only library
offering native support.

By default this library will use the credentials associated with the
current instance for authentication. To override this, see the
settings below.


Settings
--------

To use gcloud set::

    DEFAULT_FILE_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'

``GS_BUCKET_NAME``

Your Google Storage bucket name, as a string.

``GS_PROJECT_ID`` (optional)

Your Google Cloud project ID. If unset, falls back to the default
inferred from the environment.

``GS_CREDENTIALS`` (optional)

The OAuth 2 credentials to use for the connection. If unset, falls
back to the default inferred from the environment.

``GS_AUTO_CREATE_BUCKET`` (optional, default is ``False``)

If True, attempt to create the bucket if it does not exist.

``GS_AUTO_CREATE_ACL`` (optional, default is ``projectPrivate``)

ACL used when creating a new bucket, from the
`list of predefined ACLs <https://cloud.google.com/storage/docs/access-control/lists#predefined-acl>`_.
(A "JSON API" ACL is preferred but an "XML API/gsutil" ACL will be
translated.)

Note that the ACL you select must still give the service account
running the gcloud backend to have OWNER permission on the bucket. If
you're using the default service account, this means you're restricted
to the ``projectPrivate`` ACL.

``GS_FILE_CHARSET`` (optional)

Allows overriding the character set used in filenames.

``GS_FILE_OVERWRITE`` (optional: default is ``True``)

By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

``GS_MAX_MEMORY_SIZE`` (optional)

The maximum amount of memory a returned file can take up before being
rolled over into a temporary file on disk. Default is 0: Do not roll over.

Fields
------

Once you're done, default_storage will be Google Cloud Storage::

    >>> from django.core.files.storage import default_storage
    >>> print default_storage.__class__
    <class 'storages.backends.gcloud.GoogleCloudStorage'>

This way, if you define a new FileField, it will use the Google Cloud Storage::

    >>> from django.db import models
    >>> class Resume(models.Model):
    ...     pdf = models.FileField(upload_to='pdfs')
    ...     photos = models.ImageField(upload_to='photos')
    ...
    >>> resume = Resume()
    >>> print resume.pdf.storage
    <storages.backends.gcloud.GoogleCloudStorage object at ...>

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
