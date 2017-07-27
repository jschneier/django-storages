Amazon S3
=========

Usage
*****

There are two backends for interacting with Amazon's S3, one based
on boto3 and an older one based on boto. It is highly recommended that all
new projects (at least) use the boto3 backend since it has many bug fixes
and performance improvements over boto and is the future; boto is lightly
maintained if at all. The boto based backed will continue to be maintained
for the forseeable future.

For historical completeness an extreme legacy backend was removed
in version 1.2

If using the boto backend on a new project (not recommended) it is recommended
that you configure it to also use `AWS Signature Version 4`_. This can be done
by adding ``S3_USE_SIGV4 = True`` to your settings and setting the ``AWS_S3_HOST``
configuration option. For regions created after January 2014 this is your only
option if you insist on using the boto backend.

Settings
--------

To use boto3 set::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

To use the boto version of the backend set::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto.S3BotoStorage'

To allow ``django-admin.py`` collectstatic to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

Available are numerous settings. It should be especially noted the following:

``AWS_ACCESS_KEY_ID``
    Your Amazon Web Services access key, as a string.

``AWS_SECRET_ACCESS_KEY``
    Your Amazon Web Services secret access key, as a string.

``AWS_STORAGE_BUCKET_NAME``
    Your Amazon Web Services storage bucket name, as a string.

``AWS_DEFAULT_ACL`` (optional)
    If set to ``private`` changes uploaded file's Access Control List from the default permission ``public-read`` to give owner full control and remove read access from everyone else. 

``AWS_AUTO_CREATE_BUCKET`` (optional)
    If set to ``True`` the bucket specified in ``AWS_STORAGE_BUCKET_NAME`` is automatically created.

``AWS_HEADERS`` (optional - boto only, for boto3 see ``AWS_S3_OBJECT_PARAMETERS``)
    If you'd like to set headers sent with each file of the storage::

        AWS_HEADERS = {
            'Expires': 'Thu, 15 Apr 2010 20:00:00 GMT',
            'Cache-Control': 'max-age=86400',
        }

``AWS_S3_OBJECT_PARAMETERS`` (optional - boto3 only)
  Use this to set object parameters on your object (such as CacheControl)::

        AWS_S3_OBJECT_PARAMETERS = {
            'CacheControl': 'max-age=86400',
        }

``AWS_QUERYSTRING_AUTH`` (optional; default is ``True``)
    Setting ``AWS_QUERYSTRING_AUTH`` to ``False`` to remove query parameter
    authentication from generated URLs. This can be useful if your S3 buckets
    are public.

``AWS_QUERYSTRING_EXPIRE`` (optional; default is 3600 seconds)
    The number of seconds that a generated URL is valid for.

``AWS_S3_ENCRYPTION`` (optional; default is ``False``)
    Enable server-side file encryption while at rest, by setting ``encrypt_key`` parameter to True. More info available here: http://boto.cloudhackers.com/en/latest/ref/s3.html

``AWS_S3_FILE_OVERWRITE`` (optional: default is ``True``)
    By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

``AWS_S3_HOST`` (optional - boto only, default is ``s3.amazonaws.com``)

  To ensure you use `AWS Signature Version 4`_ it is recommended to set this to the host of your bucket. See the
  `S3 region list`_ to figure out the appropriate endpoint for your bucket. Also be sure to add
  ``S3_USE_SIGV4 = True`` to settings.py

  .. note::

    The signature versions are not backwards compatible so be careful about url endpoints if making this change
    for legacy projects.

``AWS_LOCATION`` (optional: default is `''`)
    A path prefix that will be prepended to all uploads

``AWS_IS_GZIPPED`` (optional: default is ``False``)
    Whether or not to enable gzipping of content types specified by ``GZIP_CONTENT_TYPES``

``GZIP_CONTENT_TYPES`` (optional: default is ``text/css``, ``text/javascript``, ``application/javascript``, ``application/x-javascript``, ``image/svg+xml``)
    When ``AWS_IS_GZIPPED`` is set to ``True`` the content types which will be gzipped

``AWS_S3_REGION_NAME`` (optional: default is ``None``)
    Name of the AWS S3 region to use (eg. eu-west-1)

``AWS_S3_USE_SSL`` (optional: default is ``True``)
    Whether or not to use SSL when connecting to S3.

``AWS_S3_ENDPOINT_URL`` (optional: default is ``None``)
    Custom S3 URL to use when connecting to S3, including scheme. Overrides ``AWS_S3_REGION_NAME`` and ``AWS_S3_USE_SSL``.

``AWS_S3_CALLING_FORMAT`` (optional: default is ``SubdomainCallingFormat()``)
    Defines the S3 calling format to use to connect to the static bucket.

``AWS_S3_SIGNATURE_VERSION`` (optional - boto3 only)

  All AWS regions support v4 of the signing protocol. To use it set this to ``'s3v4'``. It is recommended
  to do this for all new projects and required for all regions launched after January 2014. To see
  if your region is one of them you can view the `S3 region list`_.

  .. note::

    The signature versions are not backwards compatible so be careful about url endpoints if making this change
    for legacy projects.

.. _AWS Signature Version 4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
.. _S3 region list: http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region

CloudFront
~~~~~~~~~~

If you're using S3 as a CDN (via CloudFront), you'll probably want this storage
to serve those files using that::

    AWS_S3_CUSTOM_DOMAIN = 'cdn.mydomain.com'

**NOTE:** Django's `STATIC_URL` `must end in a slash`_ and the `AWS_S3_CUSTOM_DOMAIN` *must not*. It is best to set this variable indepedently of `STATIC_URL`.

.. _must end in a slash: https://docs.djangoproject.com/en/dev/ref/settings/#static-url

Keep in mind you'll have to configure CloudFront to use the proper bucket as an
origin manually for this to work.

If you need to use multiple storages that are served via CloudFront, pass the
`custom_domain` parameter to their constructors.

Storage
-------

Standard file access options are available, and work as expected::

    >>> from django.core.files.storage import default_storage
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
