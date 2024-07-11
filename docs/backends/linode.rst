Linode
======

Linode implements the S3 protocol. To use it follow the instructions in the :doc:`Amazon S3 docs <amazon-S3>` with the important caveats that you must:

- Set ``AWS_S3_REGION_NAME`` to your Linode region (such as ``eu-central-1``)
- Set ``AWS_S3_ENDPOINT_URL`` to the value of ``https://{AWS_STORAGE_BUCKET_NAME}.{AWS_REGION_NAME}.linodeobjects.com``
- Set the values of ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` to the corresponding values from Linode

