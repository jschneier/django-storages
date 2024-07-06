Scaleway
========

`Scaleway Object Storage <https://www.scaleway.com/en/docs/storage/object/>`_ implements the S3 protocol. To use it follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` with the important caveats that you must:

- Set ``AWS_BUCKET_NAME`` to the Bucket you want write to (such as ``my-chosen-bucket``)
- Set ``AWS_S3_REGION_NAME`` to your Scaleway region (such as ``nl-ams`` or ``fr-par``)
- Set ``AWS_S3_ENDPOINT_URL`` to the value of ``https://s3.${AWS_S3_REGION_NAME}.scw.cloud``
- Set ``AWS_ACCESS_KEY_ID`` to the value of your Access Key ID (i.e. ``SCW3XXXXXXXXXXXXXXXX``)
- Set ``AWS_SECRET_ACCESS_KEY`` to the value of your Secret Key (i.e. ``abcdef10-ab12-cd34-ef56-acbdef123456``)

With the settings above in place, saving a file with a name such as "my_chosen_file.txt" would be written to the following addresses:

``https://s3.nl-ams.scw.cloud/my-chosen-bucket/my_chosen_file.txt``
``https://my-chosen-bucket.s3.nl-ams.scw.cloud/my_chosen_file.txt``
