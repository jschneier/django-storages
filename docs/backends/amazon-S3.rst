Amazon S3
=========

Usage
*****

There is only one supported backend for interacting with Amazon's S3,
``S3Boto3Storage``, based on the boto3 library.

The legacy ``S3BotoStorage`` backend was removed in version 1.9. To continue getting new features you must upgrade
to the ``S3Boto3Storage`` backend by following the :ref:`migration instructions <migrating-boto-to-boto3>`.

The minimum required version of ``boto3`` is 1.4.4 although we always recommend
the most recent.

Settings
--------

To upload your media files to S3 set::

    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

To allow ``django-admin collectstatic`` to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.s3boto3.S3StaticStorage'

If you want to use something like `ManifestStaticFilesStorage`_ then you must instead use::

    STATICFILES_STORAGE = 'storages.backends.s3boto3.S3ManifestStaticStorage'

``AWS_ACCESS_KEY_ID``
    Your Amazon Web Services access key, as a string.

``AWS_SECRET_ACCESS_KEY``
    Your Amazon Web Services secret access key, as a string.

.. note::

      If ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` are not set, boto3 internally looks up IAM credentials.

``AWS_STORAGE_BUCKET_NAME``
    Your Amazon Web Services storage bucket name, as a string.

``AWS_S3_OBJECT_PARAMETERS`` (optional, default ``{}``)
  Use this to set parameters on all objects. To set these on a per-object
  basis, subclass the backend and override ``S3Boto3Storage.get_object_parameters``.

  To view a full list of possible parameters (there are many) see the `Boto3 docs for uploading files`_.
  Some of the included ones are ``CacheControl``, ``SSEKMSKeyId``, ``StorageClass``, ``Tagging`` and ``Metadata``.

``AWS_DEFAULT_ACL`` (optional; default is ``None`` which means the file will inherit the bucket's permission)

   Use this to set an ACL on your file such as ``public-read``. By default the file will inherit the bucket's ACL.
   If the ``ACL`` parameter is set in ``AWS_S3_OBJECT_PARAMETERS``, then this setting is ignored.

``AWS_QUERYSTRING_AUTH`` (optional; default is ``True``)
    Setting ``AWS_QUERYSTRING_AUTH`` to ``False`` to remove query parameter
    authentication from generated URLs. This can be useful if your S3 buckets
    are public.

``AWS_S3_MAX_MEMORY_SIZE`` (optional; default is ``0`` - do not roll over)
    The maximum amount of memory (in bytes) a file can take up before being rolled over
    into a temporary file on disk.

``AWS_QUERYSTRING_EXPIRE`` (optional; default is 3600 seconds)
    The number of seconds that a generated URL is valid for.

``AWS_S3_FILE_OVERWRITE`` (optional: default is ``True``)
    By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

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

``AWS_S3_VERIFY`` (optional: default is ``None``)
    Whether or not to verify the connection to S3. Can be set to False to not verify certificates or a path to a CA cert bundle.

``AWS_S3_ENDPOINT_URL`` (optional: default is ``None``)
    Custom S3 URL to use when connecting to S3, including scheme. Overrides ``AWS_S3_REGION_NAME`` and ``AWS_S3_USE_SSL``. To avoid ``AuthorizationQueryParametersError`` error, ``AWS_S3_REGION_NAME`` should also be set.

``AWS_S3_ADDRESSING_STYLE`` (optional: default is ``None``)
    Possible values ``virtual`` and ``path``.

``AWS_S3_PROXIES`` (optional: default is ``None``)
  A dictionary of proxy servers to use by protocol or endpoint, e.g.:
  {'http': 'foo.bar:3128', 'http://hostname': 'foo.bar:4012'}.

.. note::

  The minimum required version of ``boto3`` to use this feature is 1.4.4

``AWS_S3_SIGNATURE_VERSION`` (optional)

  As of ``boto3`` version 1.13.21 the default signature version used for generating presigned
  urls is still ``v2``. To be able to access your s3 objects in all regions through presigned
  urls, explicitly set this to ``s3v4``.

  Set this to use an alternate version such as ``s3``. Note that only certain regions
  support the legacy ``s3`` (also known as ``v2``) version. You can check to see
  if your region is one of them in the `S3 region list`_.

.. note::

  The signature versions are not backwards compatible so be careful about url endpoints if making this change
  for legacy projects.

.. _AWS Signature Version 4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
.. _S3 region list: http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
.. _list of canned ACLs: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
.. _Boto3 docs for uploading files: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.put_object
.. _ManifestStaticFilesStorage: https://docs.djangoproject.com/en/3.1/ref/contrib/staticfiles/#manifeststaticfilesstorage

.. _migrating-boto-to-boto3:

Migrating from Boto to Boto3
----------------------------

Migration from the boto-based to boto3-based backend should be straightforward and painless.

The following adjustments to settings are required:

- Rename ``AWS_HEADERS`` to ``AWS_S3_OBJECT_PARAMETERS`` and change the format of the key
  names as in the following example: ``cache-control`` becomes ``CacheControl``.
- Rename ``AWS_ORIGIN`` to ``AWS_S3_REGION_NAME``
- If ``AWS_S3_CALLING_FORMAT`` is set to ``VHostCallingFormat`` set ``AWS_S3_ADDRESSING_STYLE`` to ``virtual``
- Replace the combination of ``AWS_S3_HOST`` and ``AWS_S3_PORT`` with ``AWS_S3_ENDPOINT_URL``
- Extract the region name from ``AWS_S3_HOST`` and set ``AWS_S3_REGION_NAME``
- Replace ``AWS_S3_PROXY_HOST`` and ``AWS_S3_PROXY_PORT`` with ``AWS_S3_PROXIES``
- If using signature version ``s3v4`` you can remove ``S3_USE_SIGV4``
- If you persist urls and rely on the output to use the signature version of ``s3`` set ``AWS_S3_SIGNATURE_VERSION`` to ``s3``
- Update ``DEFAULT_FILE_STORAGE`` and/or ``STATICFILES_STORAGE`` to ``storages.backends.s3boto3.S3Boto3Storage``

Additionally, you must install ``boto3``. The minimum required version is 1.4.4
although we always recommend the most recent.

Please open an issue on the GitHub repo if any further issues are encountered or steps were omitted.

CloudFront
----------

If you're using S3 as a CDN (via CloudFront), you'll probably want this storage
to serve those files using that::

    AWS_S3_CUSTOM_DOMAIN = 'cdn.mydomain.com'

.. warning::

    Django's ``STATIC_URL`` `must end in a slash`_ and the ``AWS_S3_CUSTOM_DOMAIN`` *must not*. It is best to set this variable independently of ``STATIC_URL``.

.. _must end in a slash: https://docs.djangoproject.com/en/dev/ref/settings/#static-url

Keep in mind you'll have to configure CloudFront to use the proper bucket as an
origin manually for this to work.

If you need to use multiple storages that are served via CloudFront, pass the
`custom_domain` parameter to their constructors.

CloudFront Signed Urls
^^^^^^^^^^^^^^^^^^^^^^
If you want django-storages to generate Signed Cloudfront Urls, you can do so by following these steps:
        
- modify `settings.py` to include::

    AWS_CLOUDFRONT_KEY = os.environ.get('AWS_CLOUDFRONT_KEY', None).encode('ascii')
    AWS_CLOUDFRONT_KEY_ID = os.environ.get('AWS_CLOUDFRONT_KEY_ID', None)
    
- Generate a CloudFront Key Pair as specified in the `AWS Doc to create  CloudFront key pairs`_.

- Updated ENV vars with the corresponding values::

        AWS_CLOUDFRONT_KEY=-----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
        AWS_CLOUDFRONT_KEY_ID=APK....

.. _AWS Doc to create  CloudFront key pairs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs-procedure

django-storages will now generate `signed cloudfront urls`_

.. _signed cloudfront urls: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html

IAM Policy
----------

The IAM policy permissions needed for most common use cases are:

.. code-block:: json

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObjectAcl",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:DeleteObject",
                    "s3:PutObjectAcl"
                ],
                "Principal": {
                    "AWS": "arn:aws:iam::example-AWS-account-ID:user/example-user-name"
                },
                "Resource": [
                    "arn:aws:s3:::example-bucket-name/*",
                    "arn:aws:s3:::example-bucket-name"
                ]
            }
        ]
    }


For more information about Principal, please refer to `AWS JSON Policy Elements`_

.. _AWS JSON Policy Elements: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html

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


Overriding the default Storage class
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can override the default Storage class and create your custom storage backend. Below provides some examples and common use cases to help you get started. This section assumes you have your AWS credentials configured, e.g. ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY``.

To create a storage class using a specific bucket::

    from storages.backends.s3boto3 import S3Boto3Storage

    class MediaStorage(S3Boto3Storage):
        bucket_name = 'my-media-bucket'


Assume that you store the above class ``MediaStorage`` in a file called ``custom_storage.py`` in the project directory tree like below::

    | (your django project root directory)
    | ├── manage.py
    | ├── my_django_app
    | │   ├── custom_storage.py
    | │   └── ...
    | ├── ...

You can now use your custom storage class for default file storage in Django settings like below::

    DEFAULT_FILE_STORAGE = 'my_django_app.custom_storage.MediaStorage'

Or you may want to upload files to the bucket in some view that accepts file upload request::

    import os

    from django.views import View
    from django.http import JsonResponse

    from django_backend.custom_storages import MediaStorage

    class FileUploadView(View):
        def post(self, requests, **kwargs):
            file_obj = requests.FILES.get('file', '')

            # do your validation here e.g. file size/type check

            # organize a path for the file in bucket
            file_directory_within_bucket = 'user_upload_files/{username}'.format(username=requests.user)

            # synthesize a full file path; note that we included the filename
            file_path_within_bucket = os.path.join(
                file_directory_within_bucket,
                file_obj.name
            )

            media_storage = MediaStorage()

            if not media_storage.exists(file_path_within_bucket): # avoid overwriting existing file
                media_storage.save(file_path_within_bucket, file_obj)
                file_url = media_storage.url(file_path_within_bucket)

                return JsonResponse({
                    'message': 'OK',
                    'fileUrl': file_url,
                })
            else:
                return JsonResponse({
                    'message': 'Error: file {filename} already exists at {file_directory} in bucket {bucket_name}'.format(
                        filename=file_obj.name,
                        file_directory=file_directory_within_bucket,
                        bucket_name=media_storage.bucket_name
                    ),
                }, status=400)

A side note is that if you have ``AWS_S3_CUSTOM_DOMAIN`` setup in your ``settings.py``, by default the storage class will always use ``AWS_S3_CUSTOM_DOMAIN`` to generate url.

If your ``AWS_S3_CUSTOM_DOMAIN`` is pointing to a different bucket than your custom storage class, the ``.url()`` function will give you the wrong url. In such case, you will have to configure your storage class and explicitly specify ``custom_domain`` as below::

    class MediaStorage(S3Boto3Storage):
        bucket_name = 'my-media-bucket'
        custom_domain = '{}.s3.amazonaws.com'.format(bucket_name)

You can also decide to config your custom storage class to store files under a specific directory within the bucket::

    class MediaStorage(S3Boto3Storage):
        bucket_name = 'my-app-bucket'
        location = 'media' # store files under directory `media/` in bucket `my-app-bucket`

This is especially useful when you want to have multiple storage classes share the same bucket::

    class MediaStorage(S3Boto3Storage):
        bucket_name = 'my-app-bucket'
        location = 'media'

    class StaticStorage(S3Boto3Storage):
        bucket_name = 'my-app-bucket'
        location = 'static'

So your bucket file can be organized like as below::

    | my-app-bucket
    | ├── media
    | │   ├── user_video.mp4
    | │   ├── user_file.pdf
    | │   └── ...
    | ├── static
    | │   ├── app.js
    | │   ├── app.css
    | │   └── ...


Model
-----

An object without a file has limited functionality::

    from django.db import models
    from django.core.files.base import ContentFile

    class MyModel(models.Model):
      normal = models.FileField()

    >>> obj1 = MyModel()
    >>> obj1.normal
    <FieldFile: None>
    >>> obj1.normal.size
    Traceback (most recent call last):
    ...
    ValueError: The 'normal' attribute has no file associated with it.

Saving a file enables full functionality::

    >>> obj1.normal.save('django_test.txt', ContentFile(b'content'))
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

    >>> obj2 = MyModel()
    >>> obj2.normal.save('django_test.txt', ContentFile(b'more content'))
    >>> obj2.normal
    <FieldFile: tests/django_test.txt>
    >>> obj2.normal.size
    12

Push the objects into the cache to make sure they pickle properly::

    >>> cache.set('obj1', obj1)
    >>> cache.set('obj2', obj2)
    >>> cache.get('obj2').normal
    <FieldFile: tests/django_test.txt>

Clean up the temporary files::

    >>> obj1.normal.delete()
    >>> obj2.normal.delete()
