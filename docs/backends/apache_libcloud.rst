Apache Libcloud
===============

`Apache Libcloud`_ is an API wrapper around a range of cloud storage providers.
It aims to provide a consistent API for dealing with cloud storage (and, more
broadly, the many other services provided by cloud providers, such as device
provisioning, load balancer configuration, and DNS configuration).

Use pip to install apache-libcloud from PyPI::

    pip install apache-libcloud

As of v0.10.1, Libcloud supports the following cloud storage providers:
    * `Amazon S3`_
    * `Google Cloud Storage`_
    * `Nimbus.io`_
    * `Ninefold Cloud Storage`_
    * `Rackspace CloudFiles`_

Libcloud can also be configured with relatively little effort to support any provider
using EMC Atmos storage, or the OpenStack API.

.. _Apache Libcloud: http://libcloud.apache.org/
.. _Amazon S3: http://aws.amazon.com/s3/
.. _Google Cloud Storage: http://cloud.google.com/products/cloud-storage.html
.. _Rackspace CloudFiles: http://www.rackspace.com/cloud/cloud_hosting_products/files/
.. _Ninefold Cloud Storage: http://ninefold.com/cloud-storage/
.. _Nimbus.io: http://nimbus.io

Settings
--------

``LIBCLOUD_PROVIDERS``
~~~~~~~~~~~~~~~~~~~~~~

This setting is required to configure connections to cloud storage providers.
Each entry corresponds to a single 'bucket' of storage. You can have multiple
buckets for a single service provider (e.g., multiple S3 buckets), and you can
define buckets at multiple providers. For example, the following configuration
defines 3 providers: two buckets (``bucket-1`` and ``bucket-2``) on a US-based
Amazon S3 store, and a third bucket (``bucket-3``) on Google::


    LIBCLOUD_PROVIDERS = {
        'amazon_1': {
            'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
            'user': '<your username here>',
            'key': '<your key here>',
            'bucket': 'bucket-1',
        },
        'amazon_2': {
            'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
            'user': '<your username here>',
            'key': '<your key here>',
            'bucket': 'bucket-2',
        },
        'google': {
            'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
            'user': '<Your Google APIv1 username>',
            'key': '<Your Google APIv1 Key>',
            'bucket': 'bucket-3',
        },
    }

The values for the ``type``, ``user`` and ``key`` arguments will vary depending on
your storage provider:

    **Amazon S3**:

        **type**: ``libcloud.storage.types.Provider.S3_US_STANDARD_HOST``,

        **user**: Your AWS access key ID

        **key**: Your AWS secret access key

        If you want to use a availability zone other than the US default, you
        can use one of ``S3_US_WEST_HOST``, ``S3_US_WEST_OREGON_HOST``,
        ``S3_EU_WEST_HOST``, ``S3_AP_SOUTHEAST_HOST``, or
        ``S3_AP_NORTHEAST_HOST`` instead of ``S3_US_STANDARD_HOST``.

    **Google Cloud Storage**:

        **type**: ``libcloud.storage.types.Provider.GOOGLE_STORAGE``,

        **user**: Your Google APIv1 username (20 characters)

        **key**: Your Google APIv1 key

    **Nimbus.io**:

        **type**: ``libcloud.storage.types.Provider.NIMBUS``,

        **user**: Your Nimbus.io user ID

        **key**: Your Nimbus.io access key

    **Ninefold Cloud Storage**:

        **type**: ``libcloud.storage.types.Provider.NINEFOLD``,

        **user**: Your Atmos Access Token

        **key**: Your Atmos Shared Secret

    **Rackspace Cloudfiles**:

        **type**: ``libcloud.storage.types.Provider.CLOUDFIULES_US`` or ``libcloud.storage.types.Provider.CLOUDFIULES_UK``,

        **user**: Your Rackspace user ID

        **key**: Your Rackspace access key

You can specify any bucket name you want; however, the bucket must exist before you
can start using it. If you need to create the bucket, you can use the storage API.
For example, to create ``bucket-1`` from our previous example::

    >>> from storages.backends.apache_libcloud import LibCloudStorage
    >>> store = LibCloudStorage('amazon_1')
    >>> store.driver.create_container('bucket-1')


``DEFAULT_LIBCLOUD_PROVIDER``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you have defined your Libcloud providers, you have the option of
setting one provider as the default provider of Libcloud storage. This
is done setting ``DEFAULT_LIBCLOUD_PROVIDER`` to the key in
``LIBCLOUD_PROVIDER`` that you want to use as the default provider.
For example, if you want the ``amazon-1`` provider to be the default
provider, use::

    DEFAULT_LIBCLOUD_PROVIDER = 'amazon-1'

If ``DEFAULT_LIBCLOUD_PROVIDER`` isn't set, the Libcloud backend will assume
that the default storage backend is named ``default``. Therefore, you can
avoid settings DEFAULT_LIBCLOUD_PROVIDER by simply naming one of your
Libcloud providers ``default``::

    LIBCLOUD_PROVIDERS = {
        'default': {
            'type': ...
        },
    }


``DEFAULT_FILE_STORAGE``
~~~~~~~~~~~~~~~~~~~~~~~~

If you want your Libcloud storage to be the default Django file store, you can
set::

    DEFAULT_FILE_STORAGE = 'storages.backends.apache_libcloud.LibCloudStorage'

Your default Libcloud provider will be used as the file store.

Certificate authorities
-----------------------

Libcloud uses HTTPS connections, and in order to validate that these HTTPS connections are
correctly signed, root CA certificates must be present. On some platforms
(most notably, OS X and Windows), the required certificates may not be available
by default. To test

    >>> from storages.backends.apache_libcloud import LibCloudStorage
    >>> store = LibCloudStorage('amazon_1')
    Traceback (most recent call last):
    ...
    ImproperlyConfigured: Unable to create libcloud driver type libcloud.storage.types.Provider.S3_US_STANDARD_HOST: No CA Certificates were found in CA_CERTS_PATH.

If you get this error, you need to install a certificate authority.
`Download a certificate authority file`_, and then put the following two lines
into your settings.py::

    import libcloud.security
    libcloud.security.CA_CERTS_PATH.append("/path/to/your/cacerts.pem")

.. _Download a certificate authority file: http://curl.haxx.se/ca/cacert.pem
