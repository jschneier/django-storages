Neon Object Storage
===================

`Neon Object Storage <https://neon.com/docs/storage/get-started>`_ implements the S3 protocol. To use it as a django-storages backend:

#. Create a bucket and a storage credential for your branch in the Neon Console
#. Follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` with the following exceptions:

   * Set ``bucket_name`` to your previously created bucket
   * Set ``endpoint_url`` to your branch endpoint, ``https://<BRANCH_ID>.storage.<CELL>.<REGION>.aws.neon.tech``
   * Set ``region_name`` to your Neon region, for example ``us-east-2``
   * Set ``signature_version`` to ``s3v4`` and ``addressing_style`` to ``path``
   * Set the values of ``access_key`` and ``secret_key`` to the access key ID and secret access key of your credential

.. note::
   Access is set per bucket (``private`` or ``public_read``), so leave ``default_acl`` unset.
