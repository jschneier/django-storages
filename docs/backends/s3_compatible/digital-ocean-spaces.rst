Digital Ocean
=============

Digital Ocean Spaces implements the S3 protocol. To use it follow the instructions in the :doc:`Amazon S3 docs <../amazon-S3>` with the important caveats that you must:

- Set ``region_name`` to your Digital Ocean region (such as ``nyc3`` or ``sfo2``)
- Set ``endpoint_url`` to the value of ``https://${region_name}.digitaloceanspaces.com``
- Set the values of ``access_key`` and ``secret_key`` to the corresponding values from Digital Ocean
