Backblaze B2
============

Backblaze B2 implements an `S3 Compatible API <https://www.backblaze.com/b2/docs/s3_compatible_api.html>`_. To use it as a django-storages backend:

#. Sign up for a `Backblaze B2 account <https://www.backblaze.com/b2/sign-up.html?referrer=nopref>`_, if you have not already done so.
#. Create a public or private bucket. Note that object-level ACLs are not supported by B2 - all objects inherit their bucket's ACLs.
#. Create an `application key <https://www.backblaze.com/b2/docs/application_keys.html>`_. Best practice is to limit access to the bucket you just created.
#. Follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` with the following exceptions:

   * Set ``region_name`` to your Backblaze B2 region, for example, ``us-west-004``
   * Set ``endpoint_url`` to ``https://s3.${AWS_S3_REGION_NAME}.backblazeb2.com``
   * Set the values of ``access_key`` and ``secret_key`` to the application key id and application key you created in step 2.
