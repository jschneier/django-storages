Cloudflare R2
=============

Cloudflare R2 implements an `S3 Compatible API <https://developers.cloudflare.com/r2/api/s3/api/>`_. To use it as a django-storages backend:

#. Create an R2 bucket using Cloudflare's web panel or API
#. Follow `Cloudflare's docs`_ to create authentication tokens, locking down permissions as required
#. Follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` with the following exceptions:

   * Set ``bucket_name`` to your previously created bucket
   * Set ``endpoint_url`` to ``https://<ACCOUNT_ID>.r2.cloudflarestorage.com``
   * Set the values of ``access_key`` and ``secret_key`` to their respective Cloudflare keys

.. note::
   If you need a jurisdiction-specific endpoint or other advanced features, consult the Cloudflare docs.

.. _Cloudflare's docs: https://developers.cloudflare.com/r2/api/s3/tokens/
