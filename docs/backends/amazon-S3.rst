Amazon S3
=========

Usage
*****

There is only one supported backend for interacting with Amazon's S3,
``S3Boto3Storage``, based on the boto3 library. The backend based on the boto
library has now been officially deprecated and is due to be removed shortly.

All current users of the legacy ``S3BotoStorage`` backend are encouraged to migrate
to the ``S3Boto3Storage`` backend by following the :ref:`migration instructions <migrating-boto-to-boto3>`.

For historical completeness an extreme legacy backend was removed
in version 1.2

Settings
--------

To upload your media files to S3 set::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

To allow ``django-admin.py`` collectstatic to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

``AWS_ACCESS_KEY_ID``
    Your Amazon Web Services access key, as a string.

``AWS_SECRET_ACCESS_KEY``
    Your Amazon Web Services secret access key, as a string.

``AWS_STORAGE_BUCKET_NAME``
    Your Amazon Web Services storage bucket name, as a string.

``AWS_DEFAULT_ACL`` (optional, ``None`` or canned ACL, default ``public-read``)
    Must be either ``None`` or from the `list of canned ACLs`_. If set to ``None``
    then all files will inherit the bucket's ACL.

.. warning::

    The default value of ``public-read`` is insecure and will be changing to ``None`` in
    a future release of django-storages. Please set this explicitly to ``public-read``
    if that is the desired behavior.

``AWS_BUCKET_ACL`` (optional, default ``public-read``)
    Only used if ``AWS_AUTO_CREATE_BUCKET=True``. The ACL of the created bucket.

    Must be either ``None`` or from the `list of canned ACLs`_. If set to ``None``
    then the bucket will use the AWS account's default.

.. warning::

    The default value of ``public-read`` is insecure and will be changing to ``None`` in
    a future release of django-storages. Please set this explicitly to ``public-read``
    if that is the desired behavior.

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

``AWS_S3_MAX_MEMORY_SIZE`` (optional; default is ``0`` - do not roll over)
    The maximum amount of memory a file can take up before being rolled over
    into a temporary file on disk.

``AWS_QUERYSTRING_EXPIRE`` (optional; default is 3600 seconds)
    The number of seconds that a generated URL is valid for.

``AWS_S3_ENCRYPTION`` (optional; default is ``False``)
    Enable server-side file encryption while at rest.

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

``AWS_S3_VERIFY`` (optional: default is ``None`` - boto3 only)
    Whether or not to verify the connection to S3. Can be set to False to not verify certificates or a path to a CA cert bundle.

``AWS_S3_ENDPOINT_URL`` (optional: default is ``None``, boto3 only)
    Custom S3 URL to use when connecting to S3, including scheme. Overrides ``AWS_S3_REGION_NAME`` and ``AWS_S3_USE_SSL``.

``AWS_S3_ADDRESSING_STYLE`` (default is ``None``, boto3 only)
    Possible values ``virtual`` and ``path``.

``AWS_S3_PROXIES`` (boto3 only, default ``None``)
  A dictionary of proxy servers to use by protocol or endpoint, e.g.:
  {'http': 'foo.bar:3128', 'http://hostname': 'foo.bar:4012'}.

.. note::

  The minimum required version of ``boto3`` to use this feature is 1.4.4

``AWS_S3_CALLING_FORMAT`` (optional: default is ``SubdomainCallingFormat()``)
    Defines the S3 calling format to use to connect to the static bucket.

``AWS_S3_SIGNATURE_VERSION`` (optional - boto3 only)

  As of ``boto3`` version 1.4.4 the default signature version is ``s3v4``.

  Set this to use an alternate version such as ``s3``. Note that only certain regions
  support the legacy ``s3`` (also known as ``v2``) version. You can check to see
  if your region is one of them in the `S3 region list`_.

.. note::

  The signature versions are not backwards compatible so be careful about url endpoints if making this change
  for legacy projects.

.. _AWS Signature Version 4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
.. _S3 region list: http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
.. _list of canned ACLs: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl

.. _migrating-boto-to-boto3:

Migrating from Boto to Boto3
----------------------------

Migration from the boto-based to boto3-based backend should be straightforward and painless.

The following adjustments to settings are required:

- Rename ``AWS_HEADERS`` to ``AWS_S3_OBJECT_PARAMETERS`` and change the format of the key
  names as in the following example: ``cache-control`` becomes ``CacheControl``.
- Raname ``AWS_ORIGIN`` to ``AWS_S3_REGION_NAME``
- If ``AWS_S3_CALLING_FORMAT`` is set to ``VHostCallingFormat`` set ``AWS_S3_ADDRESSING_STYLE`` to ``virtual``
- Replace the combination of ``AWS_S3_HOST`` and ``AWS_S3_PORT`` with ``AWS_S3_ENDPOINT_URL``
- Extract the region name from ``AWS_S3_HOST`` and set ``AWS_S3_REGION_NAME``
- Replace ``AWS_S3_PROXY_HOST`` and ``AWS_S3_PROXY_PORTY`` with ``AWS_S3_PROXIES``
- If using signature version ``s3v4`` you can remove ``S3_USE_SIGV4``
- If you persist urls and rely on the output to use the signature version of ``s3`` set ``AWS_S3_SIGNATURE_VERSION`` to ``s3``
- Update ``DEFAULT_FILE_STORAGE`` and/or ``STATICFILES_STORAGE`` to ``storages.backends.boto3.S3Boto3Storage``

Additionally you must install ``boto3`` (``boto`` is no longer required).  In order to use
all currently supported features ``1.4.4`` is the minimum required version although we
always recommend the most recent.

Please open an issue on the GitHub repo if any further issues are encountered or steps were omitted.

CloudFront
----------

If you're using S3 as a CDN (via CloudFront), you'll probably want this storage
to serve those files using that::

    AWS_S3_CUSTOM_DOMAIN = 'cdn.mydomain.com'

.. warning::

    Django's ``STATIC_URL`` `must end in a slash`_ and the ``AWS_S3_CUSTOM_DOMAIN`` *must not*. It is best to set this variable indepedently of ``STATIC_URL``.

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

Clean up the temporary files::

    >>> obj1.normal.delete()
    >>> obj2.normal.delete()
    >>> obj3.default.delete()
    >>> obj4.random.delete()
