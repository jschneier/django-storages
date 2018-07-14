Google Cloud Storage
====================

This backend provides Django File API for `Google Cloud Storage <https://cloud.google.com/storage/>`
using the python library provided by Google.


Installation
------------

Use pip to install from PyPI::

    pip install django-storages[google]

Add ``storages`` to your settings.py file::

    INSTALLED_APPS = (
        ...
        'storages',
        ...
    )

Authentication
--------------
By default this library will try to use the credentials associated with the
current Google Compute Engine (GCE) instance for authentication.

#. Create a service account.
(`Google Getting Started Guide <https://cloud.google.com/docs/authentication/getting-started>`)
#. Create the key and download `your-project-XXXXX.json` file.
#. Set an environment variable of GOOGLE_APPLICATION_CREDENTIALS to path of the json file.
#. Make sure your service account has access to the bucket.
(`Using IAM Permissions <https://cloud.google.com/storage/docs/access-control/using-iam-permissions>`)


Alternatively, if you do not want to use the env variable GOOGLE_APPLICATION_CREDENTIALS
use the setting `GS_CREDENTIALS` as described below.



Getting Started
---------------
Set the default storage and bucket name in your settings.py file:

::

    DEFAULT_FILE_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'
    GS_BUCKET_NAME = 'YOUR_BUCKET_NAME_GOES_HERE'

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

Settings
--------

To use gcloud set::

    DEFAULT_FILE_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'

``GS_BUCKET_NAME``

Your Google Storage bucket name, as a string. Required.

``GS_PROJECT_ID`` (optional)

Your Google Cloud project ID. If unset, falls back to the default
inferred from the environment.

``GS_CREDENTIALS`` (optional)

The OAuth 2 credentials to use for the connection. If unset, falls
back to the default inferred from the environment
(i.e. GOOGLE_APPLICATION_CREDENTIALS)

::

    from google.oauth2 import service_account

    GS_CREDENTIALS = service_account.Credentials.from_service_account_file(
        "path/to/credentials.json"
    )


``GS_AUTO_CREATE_BUCKET`` (optional, default is ``False``)

If True, attempt to create the bucket if it does not exist.

``GS_AUTO_CREATE_ACL`` (optional, default is ``projectPrivate``)

ACL used when creating a new bucket, from the
`list of predefined ACLs <https://cloud.google.com/storage/docs/access-control/lists#predefined-acl>`_.
(A "JSON API" ACL is preferred but an "XML API/gsutil" ACL will be
translated.)

Note that the ACL you select must still give the service account
running the GCE backend to have OWNER permission on the bucket. If
you're using the default service account, this means you're restricted
to the ``projectPrivate`` ACL.

``GS_DEFAULT_ACL`` (optional, default is None)

ACL used when creating a new blob, from the
`list of predefined ACLs <https://cloud.google.com/storage/docs/access-control/lists#predefined-acl>`_.
(A "JSON API" ACL is preferred but an "XML API/gsutil" ACL will be
translated.)

For most cases, the blob will need to be set to the ``publicRead`` ACL in order for the file to viewed.
If GS_DEFAULT_ACL is not set, the blob will have the default permissions set by the bucket.


``GS_FILE_CHARSET`` (optional)

Allows overriding the character set used in filenames.

``GS_FILE_OVERWRITE`` (optional: default is ``True``)

By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

``GS_MAX_MEMORY_SIZE`` (optional)

The maximum amount of memory a returned file can take up before being
rolled over into a temporary file on disk. Default is 0: Do not roll over.

``GS_CACHE_CONTROL`` (optional: default is ``None``)

Sets Cache-Control HTTP header for the file, more about HTTP caching can be found `here <https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching#cache-control>`_

``GS_LOCATION`` (optional: default is ``''``)

Subdirectory in which the files will be stored.
Defaults to the root of the bucket.

Usage
-----

Fields
^^^^^^

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
^^^^^^^

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
^^^^^

An object without a file has limited functionality::

    >>> obj1 = Resume()
    >>> obj1.pdf
    <FieldFile: None>
    >>> obj1.pdf.size
    Traceback (most recent call last):
    ...
    ValueError: The 'pdf' attribute has no file associated with it.

Saving a file enables full functionality::

    >>> obj1.pdf.save('django_test.txt', ContentFile('content'))
    >>> obj1.pdf
    <FieldFile: tests/django_test.txt>
    >>> obj1.pdf.size
    7
    >>> obj1.pdf.read()
    'content'

Files can be read in a little at a time, if necessary::

    >>> obj1.pdf.open()
    >>> obj1.pdf.read(3)
    'con'
    >>> obj1.pdf.read()
    'tent'
    >>> '-'.join(obj1.pdf.chunks(chunk_size=2))
    'co-nt-en-t'

Save another file with the same name::

    >>> obj2 = Resume()
    >>> obj2.pdf.save('django_test.txt', ContentFile('more content'))
    >>> obj2.pdf
    <FieldFile: tests/django_test_.txt>
    >>> obj2.pdf.size
    12

Push the objects into the cache to make sure they pickle properly::

    >>> cache.set('obj1', obj1)
    >>> cache.set('obj2', obj2)
    >>> cache.get('obj2').pdf
    <FieldFile: tests/django_test_.txt>

Deleting an object deletes the file it uses, if there are no other objects still using that file::

    >>> obj2.delete()
    >>> obj2.pdf.save('django_test.txt', ContentFile('more content'))
    >>> obj2.pdf
    <FieldFile: tests/django_test_.txt>
