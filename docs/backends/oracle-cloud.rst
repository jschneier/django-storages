Oracle Cloud
=============

Oracle cloud provides S3 compatible object storage. To use it follow the instructions in the :doc:`Amazon S3 docs <amazon-S3>` on how to configure *DEFAULT_FILE_STORAGE* and *STATICFILES_STORAGE* and set the following
configurations on settings.py

- Create a `Customer Secret Key`_
- Use generated key as ``secret_key``
- And the value in the *Access Key* column as ``access_key``
- Set ``bucket_name`` with your bucket name
- Set ``region_name`` with the current region

And last but most importantly set the ``endpoint_url`` with:

    ``https://{ORACLE_NAMESPACE}.compat.objectstorage.{ORACLE_REGION}.oraclecloud.com``

The ``ORACLE_NAMESPACE`` value can be found on the bucket details page


References
----------

- `Customer Secret Key`_
- `Amazon S3 Compatibility API docs`_
- `Amazon S3 Compatibility API endpoints`_
- `Oracle object storage namespaces docs`_


.. _Oracle object storage namespaces docs: https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/understandingnamespaces.htm#Understanding_Object_Storage_Namespaces
.. _Amazon S3 Compatibility API docs: https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/s3compatibleapi.htm#
.. _Amazon S3 Compatibility API endpoints: https://docs.oracle.com/en-us/iaas/api/#/en/s3objectstorage/20160918/
.. _Customer Secret Key: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#To4
