from django.utils.encoding import filepath_to_uri
from storages.backends.s3boto3 import S3Boto3Storage


class CustomDomainSignedS3Boto3Storage(S3Boto3Storage):
    """
    S3 storage backend with signed support for custom domains
    """

    def url(self, name, parameters=None, expire=None):
        # Preserve the trailing slash after normalizing the path.
        # TODO: Handle force_http=not self.secure_urls like in s3boto
        name = self._normalize_name(self._clean_name(name))

        if expire is None:
            expire = self.querystring_expire

        params = parameters.copy() if parameters else {}
        params['Bucket'] = self.bucket.name
        params['Key'] = self._encode_name(name)
        url = self.bucket.meta.client.generate_presigned_url('get_object', Params=params,
                                                             ExpiresIn=expire)

        if name == '':
            url = "%s//%s" % (self.url_protocol, self.custom_domain)
        elif self.custom_domain:
            split_url = url.split(name)
            split_url[0] = "%s//%s" % (self.url_protocol, self.custom_domain)
            url = filepath_to_uri(name).join(split_url)

        if self.querystring_auth:
            return url
        return self._strip_signing_parameters(url)
