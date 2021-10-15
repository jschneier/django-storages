Digital Ocean
=============

Digital Ocean Spaces implements the S3 protocol. To use it follow the instructions in the :doc:`Amazon S3 docs <amazon-S3>` with the important caveats that you must:

- Set ``AWS_S3_REGION_NAME`` to your Digital Ocean region (such as ``nyc3`` or ``sfo2``)
- Set ``AWS_S3_ENDPOINT_URL`` to the value of ``https://${AWS_S3_REGION_NAME}.digitaloceanspaces.com``
- Set the values of ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` to the corresponding values from Digital Ocean

Signed urls with Digital Ocean CDN domains
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to use signed urls with a custom domain on Digital Ocean spaces.  Per the `Digital Ocean docs for the Spaces API`_::

.. note::

    You can use presigned URLs with the Spaces CDN. To do so, configure your SDK or S3 tool to use the non-CDN endpoint, generate a presigned URL for a GetObject request, then modify the hostname in the URL to be the CDN hostname (<space-name>.<region>.cdn.digitaloceanspaces.com, unless the Space uses a custom hostname).
    
To accomplish this, consider the following settings in your ``settings.py``::

    MEDIAFILES_LOCATION = 'media'
    DEFAULT_FILE_STORAGE = 'custom_storages.MediaStorage'
    AWS_PRIVSTORAGE_BUCKET_NAME = 'my-app-priv-bucket'
    AWS_S3_CUSTOM_DOMAIN = 'cdn.mydomain.com'
    AWS_S3_REGION_NAME = 'nyc3'
    AWS_S3_ENDPOINT_URL = f'https://{AWS_S3_REGION_NAME}.digitaloceanspaces.com'
    AWS_S3_SIGNATURE_VERSION = 's3'
    
Along with the following custom storage class in ``custom_storages.py`` in the root of your Django project::

    from django.conf import settings
    from storages.backends.s3boto3 import S3Boto3Storage
    from django.utils.deconstruct import deconstructible

    @deconstructible
    class PrivStorage(S3Boto3Storage):

        custom_domain = None
        bucket_name = settings.AWS_PRIVSTORAGE_BUCKET_NAME
        location = settings.MEDIAFILES_LOCATION

    s3_priv_storage = PrivStorage()
    
Digital Ocean can provide signed urls but not via a custom domain, so we have defined a custom domain but told the storage class not to use it, which will cause the url generating method to return a signed link to the object on Digital Ocean's ``digitaloceanspaces.com`` domain.  Then, we could use a template tag filter or an additional method on the storage class to return the signed url, with the Digital Ocean domain replaced by the custom domain.  The template tag in ``myapp/templatetags/myapp_tags.py`` might look like::

    from django.conf import settings
    
    @register.filter
    def cdn_url(value):
        if settings.AWS_S3_ENDPOINT_URL in value:
            cdn_domain = 'https://' + settings.AWS_S3_CUSTOM_DOMAIN
            new_url = value.replace(settings.AWS_S3_ENDPOINT_URL, cdn_domain)
            return new_url
        else:
            return value
            
In your template(s), you could then use the filter to replace the ``digitaloceanspaces.com`` domain with your custom domain after the signed url has been generated. Assuming your page model has a ``media`` instance which represents the stored object, the above filter would be used like so::

    {% load myapp_tags %}

    {{ self.media.url|cdn_url }}

If your signed url contains the ``nyc3.digitaloceanspaces.com`` endpoint you specified in ``settings.py``, that hostname will be replaced by your ``AWS_S3_CUSTOM_DOMAIN`` 

.. _Digital Ocean docs for the Spaces API: https://docs.digitalocean.com/products/spaces/resources/s3-sdk-examples/#presigned-url
