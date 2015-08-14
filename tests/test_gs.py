from django.test import TestCase
from django.core.files.base import ContentFile

from storages.backends import gs, s3boto

try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock


class GSBotoTestCase(TestCase):
    @mock.patch('storages.backends.gs.GSConnection')
    def setUp(self, GSConnection):
        self.storage = gs.GSBotoStorage()
        self.storage._connection = mock.MagicMock()


class GSStorageTestCase(GSBotoTestCase):
    def test_gs_gzip(self):
        s3boto.S3BotoStorage.gzip = False
        name = 'test_storage_save.css'
        content = ContentFile("I should be gzip'd")
        self.storage.save(name, content)
        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type', 'text/css')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={'Content-Type': 'text/css', 'Content-Encoding': 'gzip'},
            policy=self.storage.default_acl,
            rewind=True,
        )
