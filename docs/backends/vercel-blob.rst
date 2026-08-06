Vercel Blob
===========

This backend implements the Django File Storage API for `Vercel Blob`_
using the official `vercel-py`_ Python SDK.

.. _Vercel Blob: https://vercel.com/docs/storage/vercel-blob
.. _vercel-py: https://github.com/vercel/vercel-py


Installation
------------

Install the backend along with its optional dependency::

    pip install django-storages[vercel-blob]

.. note::

   The ``vercel`` package requires **Python 3.10 or newer**.  The rest of
   django-storages supports Python 3.8+, but this backend is limited by the
   SDK's own minimum requirement.


Configuration & Settings
------------------------

Django 4.2 introduced first-class support for configuring multiple storage
backends independently.  Pass options under the ``OPTIONS`` key::

    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.vercel_blob.VercelBlobStorage",
            "OPTIONS": {
                "token": "<your-read-write-token>",
            },
        },
    }

On Django < 4.2 define::

    DEFAULT_FILE_STORAGE = "storages.backends.vercel_blob.VercelBlobStorage"
    VERCEL_BLOB_TOKEN = "<your-read-write-token>"

The settings documented below are available both as ``OPTIONS`` keys (or
constructor keyword arguments when sub-classing) and as global Django
settings prefixed with ``VERCEL_BLOB_``.


Authentication
--------------

Vercel Blob uses a single read-write bearer token to authenticate all API
calls.  Obtain a token from the Vercel dashboard under
**Storage → <your store> → Tokens**, or by running::

    vercel env pull

The token is resolved in the following order:

1. The ``token`` option / ``VERCEL_BLOB_TOKEN`` Django setting.
2. The ``BLOB_READ_WRITE_TOKEN`` environment variable.
3. The ``VERCEL_BLOB_READ_WRITE_TOKEN`` environment variable.

.. warning::

   Keep the read-write token secret.  It grants full read and write access
   to your Blob store.  Never commit it to source control; use environment
   variables or a secrets manager instead.


Settings
--------

``token`` or ``VERCEL_BLOB_TOKEN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  **Required**

  The Vercel Blob read-write bearer token used to authenticate all API
  requests.  Falls back to the ``BLOB_READ_WRITE_TOKEN`` and
  ``VERCEL_BLOB_READ_WRITE_TOKEN`` environment variables if not set via
  Django settings.

``access`` or ``VERCEL_BLOB_ACCESS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  default: ``"public"``

  Access mode for blobs created by this backend.  Must be either
  ``"public"`` or ``"private"``.

  * **public** – blobs are readable by anyone who knows the URL.
  * **private** – blobs require an ``Authorization: Bearer <token>``
    header to download.  See :ref:`vercel-blob-private-blobs` for serving
    private files from a Django view.

``location`` or ``VERCEL_BLOB_LOCATION``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  default: ``""``

  An optional path prefix applied to every object stored or retrieved by
  this backend.  Use it to namespace files within a shared Blob store.
  For example, setting ``location = "media"`` stores
  ``profile_photos/avatar.jpg`` as ``media/profile_photos/avatar.jpg``.

``file_overwrite`` or ``VERCEL_BLOB_FILE_OVERWRITE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  default: ``True``

  When ``True``, saving a file whose name already exists overwrites the
  existing blob.  Set to ``False`` to have Django append a unique suffix to
  the filename instead.

``default_content_type`` or ``VERCEL_BLOB_DEFAULT_CONTENT_TYPE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  default: ``"application/octet-stream"``

  The MIME type used when the content type cannot be guessed from the file
  name and the file-like object does not expose a ``content_type``
  attribute.

``max_memory_size`` or ``VERCEL_BLOB_MAX_MEMORY_SIZE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  default: ``0``

  The maximum number of bytes to hold in memory when buffering downloaded
  content before rolling over to a temporary file on disk (passed directly
  to :class:`~tempfile.SpooledTemporaryFile`).  ``0`` means "never roll
  over".


Example Configuration
---------------------

Minimal setup for public media files::

    # settings.py
    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.vercel_blob.VercelBlobStorage",
            "OPTIONS": {
                "token": env("BLOB_READ_WRITE_TOKEN"),
            },
        },
    }

Private file store with a location prefix::

    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.vercel_blob.VercelBlobStorage",
            "OPTIONS": {
                "token": env("BLOB_READ_WRITE_TOKEN"),
                "access": "private",
                "location": "media",
                "file_overwrite": False,
            },
        },
    }


.. _vercel-blob-private-blobs:

Serving Private Blobs
---------------------

Private blobs require an ``Authorization: Bearer <token>`` header for every
download request.  Because :meth:`~storages.backends.vercel_blob.VercelBlobStorage.url`
returns the raw private blob URL (which is **not** directly accessible in a
browser), you must proxy private files through a Django view.

Example proxy view::

    import httpx
    from django.conf import settings
    from django.http import StreamingHttpResponse

    from storages.backends.vercel_blob import VercelBlobStorage


    def serve_private_blob(request, path):
        storage = VercelBlobStorage()
        blob_url = storage.url(path)

        headers = {"Authorization": f"Bearer {storage.token}"}
        with httpx.stream("GET", blob_url, headers=headers) as response:
            django_response = StreamingHttpResponse(
                response.iter_bytes(),
                content_type=response.headers.get("content-type", "application/octet-stream"),
            )
            return django_response

Wire it up in your URL configuration::

    from django.urls import path
    from . import views

    urlpatterns = [
        path("files/<path:path>", views.serve_private_blob, name="private-blob"),
    ]

.. note::

    The example above requires ``httpx`` (already installed as a transitive
    dependency of the ``vercel`` package).  Add authentication and
    authorisation checks appropriate for your application before using this
    view in production.


URL Behaviour
-------------

The :meth:`~storages.backends.vercel_blob.VercelBlobStorage.url` method
constructs the canonical Vercel Blob URL without making a network request by
extracting the store ID from the bearer token.

**Public blob URL format**::

    https://{storeId}.public.blob.vercel-storage.com/{pathname}

**Private blob URL format**::

    https://{storeId}.private.blob.vercel-storage.com/{pathname}

.. note::

    Vercel Blob does **not** support presigned or time-limited URLs.  There
    is no equivalent to S3's ``generate_presigned_url`` or GCS's
    ``generate_signed_url``.


Security Considerations
-----------------------

* Store the read-write token in an environment variable, never in source
  code or version control.
* Use ``"private"`` access for any files that should not be publicly
  readable.
* Private blob URLs returned by ``url()`` must never be embedded directly
  in HTML — they require a bearer token to access and are only suitable
  for server-side fetching.
* The ``location`` setting provides logical namespacing, **not** security
  isolation.  All blobs in the same Vercel store share the same
  read-write token.


Limitations
-----------

* **No presigned / expiring URLs.**  Vercel Blob does not support
  time-limited download URLs.

* **Private blobs require a proxy.**  Browser clients cannot fetch private
  blobs directly; a server-side proxy view is required (see
  :ref:`vercel-blob-private-blobs`).

* **Reads are fully buffered.**  The sync SDK loads the entire blob content
  into memory before returning it to Django.  For very large files consider
  using a dedicated download endpoint with streaming instead of relying on
  the storage's ``open()`` method.

* **Python 3.10+ only.**  The ``vercel`` SDK requires Python 3.10 or newer.

* **No user-defined metadata.**  Vercel Blob does not expose a general
  key-value metadata API for blobs.

* **No GZIP compression.**  The backend does not gzip content before
  uploading.  Use a reverse proxy (e.g. nginx) or CDN-level compression if
  needed.

* **listdir may be slow on large stores.**  The Vercel Blob list API is
  paginated; :meth:`~storages.backends.vercel_blob.VercelBlobStorage.listdir`
  fetches all pages synchronously, which may cause noticeable latency for
  stores with thousands of objects.
