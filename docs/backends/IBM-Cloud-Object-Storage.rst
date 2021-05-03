IBM Cloud Object Storage
=========

Usage
*****

This provides backend support for IBM Cloud Object storage, wrapping around
amazon-s3 backend classes. Supported backend ``IBMCloudObjectStorage``, based
on the ``COSBoto3Storage`` class.


The minimum required version of ``boto3`` is 1.4.4 although we always recommend
the most recent.

Settings
--------

To upload your media files to COS set::

    DEFAULT_FILE_STORAGE = 'storages.backends.ibm_cos.IBMCloudObjectStorage'

To allow ``django-admin collectstatic`` to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.ibm_cos.IBMCOSStaticStorage'

If you want to use something like `ManifestStaticFilesStorage`_ then you must instead use::

    STATICFILES_STORAGE = 'storages.backends.ibm_cos.IBMCOSManifestStaticStorage'

``IBM_COS_ACCESS_KEY_ID``
    Your IBM COS HMAC access key, as a string.

``IBM_COS_SECRET_ACCESS_KEY``
    Your IBM COS HMAC secret access key, as a string.

.. note::

      If ``IBM_COS_ACCESS_KEY_ID`` and ``IBM_COS_SECRET_ACCESS_KEY`` are not set, boto3 internally looks up IAM credentials.

``IBM_COS_BUCKET_NAME``
    Your IBM storage bucket name, as a string.

``IBM_COS_OBJECT_PARAMETERS`` (optional, default ``{}``)
  Use this to set parameters on all objects. To set these on a per-object
  basis, subclass the backend and override ``IBMCloudObjectStorage.get_object_parameters``.

  To view a full list of possible parameters (there are many) see the `Boto3 docs for uploading files`_.
  Some of the included ones are ``CacheControl``, ``SSEKMSKeyId``, ``StorageClass``, ``Tagging`` and ``Metadata``.

``IBM_DEFAULT_ACL`` (optional; default is ``None`` which means the file will inherit the bucket's permission)

   Use this to set an ACL on your file such as ``public-read``. By default the file will inherit the bucket's ACL.
   If the ``ACL`` parameter is set in ``IBM_COS_OBJECT_PARAMETERS``, then this setting is ignored.

``IBM_QUERYSTRING_AUTH`` (optional; default is ``True``)
    Setting ``IBM_QUERYSTRING_AUTH`` to ``False`` to remove query parameter
    authentication from generated URLs. This can be useful if your COS buckets
    are public.

``IBM_COS_MAX_MEMORY_SIZE`` (optional; default is ``0`` - do not roll over)
    The maximum amount of memory (in bytes) a file can take up before being rolled over
    into a temporary file on disk.

``IBM_QUERYSTRING_EXPIRE`` (optional; default is 3600 seconds)
    The number of seconds that a generated URL is valid for.

``IBM_COS_FILE_OVERWRITE`` (optional: default is ``True``)
    By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

.. note::

    The signature versions are not backwards compatible so be careful about url endpoints if making this change
    for legacy projects.

``IBM_LOCATION`` (optional: default is `''`)
    A path prefix that will be prepended to all uploads

``IBM_IS_GZIPPED`` (optional: default is ``False``)
    Whether or not to enable gzipping of content types specified by ``GZIP_CONTENT_TYPES``

``GZIP_CONTENT_TYPES`` (optional: default is ``text/css``, ``text/javascript``, ``application/javascript``, ``application/x-javascript``, ``image/svg+xml``)
    When ``IBM_IS_GZIPPED`` is set to ``True`` the content types which will be gzipped

``IBM_COS_REGION_NAME`` (optional: default is ``None``)
    Name of the IBM COS region to use (eg. eu-west-1)

``IBM_COS_USE_SSL`` (optional: default is ``True``)
    Whether or not to use SSL when connecting to COS.

``IBM_COS_VERIFY`` (optional: default is ``None``)
    Whether or not to verify the connection to COS. Can be set to False to not verify certificates or a path to a CA cert bundle.

``IBM_COS_ENDPOINT_URL`` (optional: default is ``None``)
    Custom COS URL to use when connecting to COS, including scheme. Overrides ``IBM_COS_REGION_NAME`` and ``IBM_COS_USE_SSL``. To avoid ``AuthorizationQueryParametersError`` error, ``IBM_COS_REGION_NAME`` should also be set.

``IBM_COS_ADDRESSING_STYLE`` (optional: default is ``None``)
    Possible values ``virtual`` and ``path``.

``IBM_COS_PROXIES`` (optional: default is ``None``)
  A dictionary of proxy servers to use by protocol or endpoint, e.g.:
  {'http': 'foo.bar:3128', 'http://hostname': 'foo.bar:4012'}.

.. note::

  The minimum required version of ``boto3`` to use this feature is 1.4.4



