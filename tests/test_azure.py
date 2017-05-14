from storages.backends import azure_storage
from django.test import TestCase
try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock


class AzureStorageTest(TestCase):

    def setUp(self, *args):
        self.storage = azure_storage.AzureStorage()
        self.storage._connection = mock.MagicMock()

    def test_blob_exists(self):
        self.storage.connection.exists.return_value = True
        blob_name = "blob"
        exists = self.storage.exists(blob_name)
        self.assertTrue(exists)
        self.storage.connection.exists.assert_called_once_with(blob_name)

    def test_blob_doesnt_exists(self):
        self.storage.connection.exists.return_value = False
        blob_name = "blob"
        exists = self.storage.exists(blob_name)
        self.assertFalse(exists)
        self.storage.connection.exists.assert_called_once_with(blob_name)

    def test_blob_open_read(self):
        mocked_binary = b"mocked test"

        def mocked_stream(*args, **kwargs):
            stream = kwargs['stream']
            stream.write(mocked_binary)

        self.storage.connection.get_blob_to_stream.side_effect = mocked_stream
        with self.storage.open("name", "rb") as f:
            content = f.read()
        self.assertEqual(mocked_binary, content)

