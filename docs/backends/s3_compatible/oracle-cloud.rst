Oracle Cloud
=============

Oracle Cloud provides an S3 compatible object storage. To use it: the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` replacing:

#. Create a `Customer Secret Key`_
#. Create a bucket

Then follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` documentation replacing:

- ``secret_key`` with the value previously generated
- ``access_key`` with the value in the **Access Key** column
- ``bucket_name`` with the bucket name
- ``region_name`` with the current region
- ``endpoint_url`` with ``https://{ORACLE_NAMESPACE}.compat.objectstorage.{ORACLE_REGION}.oraclecloud.com``

.. note::
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
