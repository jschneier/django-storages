from unittest import mock
from django.test import TestCase
from storages.backends import ibm_cos

class IBMCOSTestCase(TestCase):
    def setUp(self):
        self.storage = ibm_cos.IBMCloudObjectStorage()
        self.storage._connections.connection = mock.MagicMock()

class IBMCOSStorageTests(IBMCOSTestCase):
   def test_get_default_settings(self):
       results = self.storage.get_default_settings()
       self.assertIsInstance(results, dict)
       default_setting_keys: list = ["access_key", "secret_key", "file_overwrite", "object_parameters", "bucket_name", "querystring_auth", "querystring_expire", "signature_version", "location", "custom_domain", "addressing_style", "secure_urls", "file_name_charset", "gzip", "gzip_content_types", "url_protocol", "endpoint_url", "proxies", "region_name", "use_ssl", "verify", "max_memory_size", "default_acl"]
       for setting_key in default_setting_keys:
           self.assertIn(setting_key, results.keys())
           