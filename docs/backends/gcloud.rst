Google Cloud Storage
====================

This backend provides Django File API for `Google Cloud Storage <https://cloud.google.com/storage/>`_
using the Python library provided by Google.


Installation
------------

Use pip to install from PyPI::

    pip install django-storages[google]

Configuration & Settings
------------------------

Django 4.2 changed the way file storage objects are configured. In particular, it made it easier to independently configure
storage backends and add additional ones. To configure multiple storage objects pre Django 4.2 required subclassing the backend
because the settings were global, now you pass them under the key ``OPTIONS``. For example, to save media files to GCS on Django
>= 4.2 you'd define::


  STORAGES = {
      "default": {
          "BACKEND": "storages.backends.gcloud.GoogleCloudStorage",
          "OPTIONS": {
            ...your_options_here
          },
      },
  }

On Django < 4.2 you'd instead define::

    DEFAULT_FILE_STORAGE = "storages.backends.gcloud.GoogleCloudStorage"

To put static files on GCS via ``collectstatic`` on Django >= 4.2 you'd include the ``staticfiles`` key (at the same level as
``default`` above inside of the ``STORAGES`` dictionary while on Django < 4.2 you'd instead define::

    STATICFILES_STORAGE = "storages.backends.gcloud.GoogleCloudStorage"

The settings documented in the following sections include both the key for ``OPTIONS`` (and subclassing) as
well as the global value. Given the significant improvements provided by the new API, migration is strongly encouraged.

Authentication Settings
~~~~~~~~~~~~~~~~~~~~~~~
By default, this library will try to use the credentials associated with the
current Google Cloud infrastructure/environment for authentication.

In most cases, the default service accounts are not sufficient to read/write and sign files in GCS, so you will need to create a dedicated service account:

#. Create a service account. (`Google Getting Started Guide <https://cloud.google.com/docs/authentication/getting-started>`__)
#. Make sure your service account has access to the bucket and appropriate permissions. (`Using IAM Permissions <https://cloud.google.com/storage/docs/access-control/using-iam-permissions>`__)
#. Ensure this service account is associated to the type of compute being used (Google Compute Engine (GCE), Google Kubernetes Engine (GKE), Google Cloud Run (GCR), etc)

For development use cases, or other instances outside Google infrastructure:

#. Create the key and download ``your-project-XXXXX.json`` file.
#. Ensure the key is mounted/available to your running Django app.
#. Set an environment variable of GOOGLE_APPLICATION_CREDENTIALS to the path of the json file.

Alternatively, you can use the setting ``credentials`` or ``GS_CREDENTIALS`` as described below.


Settings
~~~~~~~~

``bucket_name`` or ``GS_BUCKET_NAME``

  **Required**

  The name of the GCS bucket that will host the files.

``project_id`` or ``GS_PROJECT_ID``

  default: ``None``

  Your Google Cloud project ID. If unset, falls back to the default inferred from the environment.

``gzip`` or ``GS_IS_GZIPPED``

  default: ``False``

  Whether or not to enable gzipping of content types specified by ``gzip_content_types``.

``gzip_content_types`` or ``GZIP_CONTENT_TYPES``

  default: ``(text/css,text/javascript,application/javascript,application/x-javascript,image/svg+xml)``

  The list of content types to be gzipped when ``gzip`` is ``True``.

.. _gs-creds:

``credentials`` or ``GS_CREDENTIALS``

  default: ``None``

  The OAuth 2 credentials to use for the connection. If unset, falls back to the default inferred from the environment
  (i.e. ``GOOGLE_APPLICATION_CREDENTIALS``)::

    from google.oauth2 import service_account

    GS_CREDENTIALS = service_account.Credentials.from_service_account_file(
        "path/to/credentials.json"
    )

.. _gs-default-acl:

``default_acl`` or ``GS_DEFAULT_ACL``

  default: ``None``

  ACL used when creating a new blob, from the
  `list of predefined ACLs <https://cloud.google.com/storage/docs/access-control/lists#predefined-acl>`_.
  (A "JSON API" ACL is preferred but an "XML API/gsutil" ACL will be
  translated.)

  For most cases, the blob will need to be set to the ``publicRead`` ACL in order for the file to be viewed.
  If ``default_acl`` is not set, the blob will have the default permissions set by the bucket.

  ``publicRead`` files will return a public, non-expiring url. All other files return
  a signed (expiring) url.

.. note::
   GS_DEFAULT_ACL must be set to 'publicRead' to return a public url. Even if you set
   the bucket to public or set the file permissions directly in GCS to public.

.. note::
    When using this setting, make sure you have ``fine-grained`` access control enabled on your bucket,
    as opposed to ``Uniform`` access control, or else, file  uploads will return with HTTP 400. If you
    already have a bucket with ``Uniform`` access control set to public read, please keep
    ``GS_DEFAULT_ACL`` to ``None`` and set ``GS_QUERYSTRING_AUTH`` to ``False``.

``querystring_auth`` or ``GS_QUERYSTRING_AUTH``

  default: ``True``

  If set to ``False`` it forces the url not to be signed. This setting is useful if you need to have a
  bucket configured with ``Uniform`` access control configured with public read. In that case you should
  force the flag ``GS_QUERYSTRING_AUTH = False`` and ``GS_DEFAULT_ACL = None``

``file_overwrite`` or ``GS_FILE_OVERWRITE``

  default: ``True``

  By default files with the same name will overwrite each other. Set this to ``False`` to have extra characters appended.

``max_memory_size`` or ``GS_MAX_MEMORY_SIZE``

  default: ``0`` i.e do not rollover

  The maximum amount of memory a returned file can take up (in bytes) before being
  rolled over into a temporary file on disk. Default is 0: Do not roll over.

``blob_chunk_size`` or ``GS_BLOB_CHUNK_SIZE``

  default: ``None``

  The size of blob chunks that are sent via resumable upload. If this is not set then the generated request
  must fit in memory. Recommended if you are going to be uploading large files.

.. note::

   This must be a multiple of 256K (1024 * 256)

``object_parameters`` or ``GS_OBJECT_PARAMETERS``

  default: `{}`

  Dictionary of key-value pairs mapping from blob property name to value.

  Use this to set parameters on all objects. To set these on a per-object
  basis, subclass the backend and override ``GoogleCloudStorage.get_object_parameters``.

  The valid property names are ::

    acl
    cache_control
    content_disposition
    content_encoding
    content_language
    content_type
    metadata
    storage_class

  If not set, the ``content_type`` property will be guessed.

  If set, ``acl`` overrides :ref:`GS_DEFAULT_ACL <gs-default-acl>`.

.. warning::

   Do not set ``name``. This is set automatically based on the filename.

``custom_endpoint`` or ``GS_CUSTOM_ENDPOINT``

  default: ``None``

  Sets a `custom endpoint <https://cloud.google.com/storage/docs/request-endpoints>`_,
  that will be used instead of ``https://storage.googleapis.com`` when generating URLs for files.

``location`` or ``GS_LOCATION``

  default: ``''``

  Subdirectory in which files will be stored.

``expiration`` or ``GS_EXPIRATION``

  default: ``timedelta(seconds=86400)``)

  The time that a generated URL is valid before expiration. The default is 1 day.
  Public files will return a url that does not expire. Files will be signed by
  the credentials provided to django-storages (See :ref:`GS Credentials <gs-creds>`).

  Note: Default Google Compute Engine (GCE) Service accounts are
  `unable to sign urls <https://googlecloudplatform.github.io/google-cloud-python/latest/storage/blobs.html#google.cloud.storage.blob.Blob.generate_signed_url>`_.

  The ``expiration`` value is handled by the underlying `Google library  <https://googlecloudplatform.github.io/google-cloud-python/latest/storage/blobs.html#google.cloud.storage.blob.Blob.generate_signed_url>`_.
  It supports `timedelta`, `datetime`, or `integer` seconds since epoch time.

  Note: The maximum value for this option is 7 days (604800 seconds) in version `v4` (See this `Github issue  <https://github.com/googleapis/python-storage/issues/456#issuecomment-856884993>`_)
