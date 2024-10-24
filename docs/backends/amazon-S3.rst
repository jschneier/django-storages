Amazon S3
=========

This backend implements the Django File Storage API for Amazon Web Services's (AWS) Simple Storage Service (S3).

Installation
------------

The backend is based on the boto3 library which must be installed; the minimum required version is 1.4.4 although
we always recommend the most recent. Either add it to your requirements or use the optional ``s3`` extra e.g::

  pip install django-storages[s3]

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to save media files to S3 on Django
>= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.s3.S3Storage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.s3.S3Storage"

To put static files on S3 via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default``) in the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.s3.S3Storage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Authentication Settings
~~~~~~~~~~~~~~~~~~~~~~~

There are several different methods for specifying the AWS credentials used to create the S3 client.  In the order that ``S3Storage``
searches for them:

#. ``session_profile`` or ``AWS_S3_SESSION_PROFILE``
#. ``access_key`` or ``AWS_S3_ACCESS_KEY_ID`` or ``AWS_ACCESS_KEY_ID``
#. ``secret_key`` or ``AWS_S3_SECRET_ACCESS_KEY`` or ``AWS_SECRET_ACCESS_KEY``
#. ``security_token`` or ``AWS_SESSION_TOKEN`` or ``AWS_SECURITY_TOKEN``
#. The environment variables AWS_S3_ACCESS_KEY_ID and AWS_S3_SECRET_ACCESS_KEY
#. The environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
#. The environment variables AWS_SESSION_TOKEN and AWS_SECURITY_TOKEN
#. Use Boto3's default session

Settings
~~~~~~~~

``bucket_name`` or ``AWS_STORAGE_BUCKET_NAME``

  **Required**

  The name of the S3 bucket that will host the files.

``object_parameters`` or ``AWS_S3_OBJECT_PARAMETERS``

  Default: ``{}``

  Use this to set parameters on all objects. To set these on a per-object
  basis, subclass the backend and override ``S3Storage.get_object_parameters``.

  To view a full list of possible parameters (there are many) see the `Boto3 docs for uploading files`_; an incomplete list includes: ``CacheControl``, ``SSEKMSKeyId``, ``StorageClass``, ``Tagging`` and ``Metadata``.

``default_acl`` or ``AWS_DEFAULT_ACL``

  Default: ``None`` - the file will be ``private`` per Amazon's default

  Use this to set an ACL on your file such as ``public-read``. If not set the file will be ``private`` per Amazon's default.
  If the ``ACL`` parameter is set in ``object_parameters``, then this setting is ignored.

  Options such as ``public-read`` and ``private`` come from the `list of canned ACLs`_.

``querystring_auth`` or ``AWS_QUERYSTRING_AUTH``

  Default: ``True``

  Setting ``AWS_QUERYSTRING_AUTH`` to ``False`` to remove query parameter
  authentication from generated URLs. This can be useful if your S3 buckets
  are public.

``max_memory_size`` or ``AWS_S3_MAX_MEMORY_SIZE``

  Default: ``0`` i.e do not roll over

  The maximum amount of memory (in bytes) a file can take up before being rolled over
  into a temporary file on disk.

``querystring_expire`` or ``AWS_QUERYSTRING_EXPIRE``

  Default: ``3600``

  The number of seconds that a generated URL is valid for.

``url_protocol`` or ``AWS_S3_URL_PROTOCOL``

  Default: ``https:``

  The protocol to use when constructing a custom domain, ``custom_domain`` must be ``True`` for this to have any effect.

  .. note::
    Must end in a ``:``

``file_overwrite`` or ``AWS_S3_FILE_OVERWRITE``

  Default: ``True``

  By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

``location`` or ``AWS_LOCATION``

  Default: ``''``

  A path prefix that will be prepended to all uploads.

``gzip`` or ``AWS_IS_GZIPPED``

  Default: ``False``

  Whether or not to enable gzipping of content types specified by ``gzip_content_types``.

``gzip_content_types`` or ``GZIP_CONTENT_TYPES``

  Default: ``(text/css,text/javascript,application/javascript,application/x-javascript,image/svg+xml)``

  The list of content types to be gzipped when ``gzip`` is ``True``.

``region_name`` or ``AWS_S3_REGION_NAME``

  Default: ``None``

  Name of the AWS S3 region to use (eg. eu-west-1)

``use_ssl`` or ``AWS_S3_USE_SSL``

  Default: ``True``

  Whether or not to use SSL when connecting to S3, this is passed to the boto3 session resource constructor.

``verify`` or ``AWS_S3_VERIFY``

  Default: ``None``

  Whether or not to verify the connection to S3. Can be set to False to not verify certificates or a path to a CA cert bundle.

``endpoint_url`` or ``AWS_S3_ENDPOINT_URL``

  Default: ``None``

  Custom S3 URL to use when connecting to S3, including scheme. Overrides ``region_name`` and ``use_ssl``.
  To avoid ``AuthorizationQueryParametersError`` errors, ``region_name`` should also be set.

``addressing_style`` or ``AWS_S3_ADDRESSING_STYLE``

  Default: ``None``

  Possible values ``virtual`` and ``path``.

``proxies`` or ``AWS_S3_PROXIES``

  Default: ``None``

  Dictionary of proxy servers to use by protocol or endpoint, e.g.::

    {'http': 'foo.bar:3128', 'http://hostname': 'foo.bar:4012'}.

``transfer_config`` or ``AWS_S3_TRANSFER_CONFIG``

  Default: ``None``

  Set this to customize the transfer config options such as disabling threads for ``gevent`` compatibility;
  See the `Boto3 docs for TransferConfig`_ for more info.


``custom_domain`` or ``AWS_S3_CUSTOM_DOMAIN``

  Default: ``None``

  Set this to specify a custom domain for constructed URLs.

  .. note::
     You'll have to configure CloudFront to use the bucket as an origin for this to
     work.

     If your CloudFront config restricts viewer access you will also need to provide
     ``cloudfront_key`` / ``AWS_CLOUDFRONT_KEY`` and ``cloudfront_key_id`` /
     ``AWS_CLOUDFRONT_KEY_ID``; See those settings and
     :ref:`cloudfront-signed-url-header` for more info.

     If you have more than one storage with different viewer access permissions, you
     can provide ``cloudfront_signer=None`` to disable signing on one or more
     storages.

  .. warning::

    Django’s STATIC_URL must end in a slash and this must not. It is best to set this variable independently of STATIC_URL.

``cloudfront_key`` or ``AWS_CLOUDFRONT_KEY``

  Default: ``None``

  A private PEM encoded key to use in a ``boto3`` ``CloudFrontSigner``; See
  :ref:`cloudfront-signed-url-header` for more info.

``cloudfront_key_id`` or ``AWS_CLOUDFRONT_KEY_ID``

  Default: ``None``

  The AWS key ID for the private key provided with ``cloudfront_key`` /
  ``AWS_CLOUDFRONT_KEY``; See :ref:`cloudfront-signed-url-header` for more info.

``cloudfront_signer``

  Default: omitted

  By default the ``cloudfront_signer`` is generated based on the CloudFront key and ID
  provided. If both are provided URLs will be signed and will work for distributions
  with restricted viewer access, but if neither are provided then URLs will not be
  signed and will work for distributions with unrestricted viewer access.

  If you require a custom CloudFront signer you may pass a ``boto3``
  ``CloudFrontSigner`` instance that can sign URLs, and to disable signing you may pass
  ``None``.

``signature_version`` or ``AWS_S3_SIGNATURE_VERSION``

  Default: ``None``

  The default signature version is ``s3v4``. Set this to ``s3`` to use the legacy
  signing scheme (aka ``v2``). Note that only certain regions support that version.
  You can check to see if your region is one of them in the `S3 region list`_.

  .. warning::

    The signature versions are not backwards compatible so be careful about url endpoints if making this change
    for legacy projects.

``client_config`` or ``AWS_S3_CLIENT_CONFIG``

  Default: ``None``

  An instance of ``botocore.config.Config`` to do advanced configuration of the client such as
  ``max_pool_connections``. See all options in the `Botocore docs`_.

  .. note::

    Setting this overrides the settings for ``addressing_style``, ``signature_version`` and
    ``proxies``. Include them as arguments to your ``botocore.config.Config`` class if you need them.

.. _AWS Signature Version 4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
.. _S3 region list: https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_region
.. _list of canned ACLs: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl
.. _Boto3 docs for uploading files: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.put_object
.. _Boto3 docs for TransferConfig: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/customizations/s3.html#boto3.s3.transfer.TransferConfig
.. _ManifestStaticFilesStorage: https://docs.djangoproject.com/en/3.1/ref/contrib/staticfiles/#manifeststaticfilesstorage
.. _Botocore docs: https://botocore.amazonaws.com/v1/documentation/api/latest/reference/config.html#botocore.config.Config

.. _cloudfront-signed-url-header:

CloudFront Signed URLs
----------------------

If you want to generate signed Cloudfront URLs, you can do so by following these steps:

#. Generate a CloudFront Key Pair as specified in the `AWS docs`_.
#. Add ``cloudfront_key`` and ``cloudfront_key_id`` as above with the generated settings
#. Install one of `cryptography`_ or `rsa`_
#. Set both ``cloudfront_key_id/AWS_CLOUDFRONT_KEY_ID`` and ``cloudfront_key/AWS_CLOUDFRONT_KEY``

django-storages will now generate `signed cloudfront urls`_.

.. _AWS docs: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs-procedure
.. _signed cloudfront urls: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html

.. _cryptography: https://pypi.org/project/cryptography/
.. _rsa: https://pypi.org/project/rsa/

IAM Policy
----------

The IAM policy definition needed for the most common use case is:

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
