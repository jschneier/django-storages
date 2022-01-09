Alibaba OSS
=============

Alibaba Cloud Object Storage Service is compatible with the S3 protocol. To use it follow the instructions in the :doc:`Amazon S3 docs <amazon-S3>` with the important caveats that you must:

- Set ``AWS_S3_ADDRESSING_STYLE`` to ``virtual`` (For security reasons, OSS supports only virtual hosted style access)
- Set ``AWS_S3_REGION_NAME`` to your OSS region (such as ``oss-cn-shanghai`` or ``oss-cn-hangzhou``)
- Set ``AWS_S3_ENDPOINT_URL`` to the value of ``https://${AWS_S3_REGION_NAME}.aliyuncs.com``
- Set the values of ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` to the corresponding values from OSS

.. note::

  Alibaba OSS are not fully compatible so there are some difference between them.

- see `Use S3 API operations to access OSS after migration`_.
- see `Compatible S3 API operations`_.

.. _Use S3 API operations to access OSS after migration: https://www.alibabacloud.com/help/doc-detail/64919.htm#title-zhf-v8d-71i
.. _Compatible S3 API operations: https://www.alibabacloud.com/help/doc-detail/64919.htm#title-cds-fai-yxp
.. _
