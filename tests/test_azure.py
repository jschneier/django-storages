try:
    from unittest.mock import patch
except ImportError:  # Python 3.2 and below
    from mock import patch
from django.test import TestCase
from django.core.files.base import ContentFile
from storages.backends.azure_storage import AzureStorage


class AzureTestCase(TestCase):
    def setUp(self):
        self.instance = AzureStorage()

    @patch('storages.backends.azure_storage.AzureStorage.connection')
    def test_open_type(self, mock_connection):
        """
        _open() should return binary or text ContentFiles depending on the
        mode string
        """
        mock_connection.get_blob.return_value = b'This is a test blob'

        # Read this fake blob in binary mode (rb or None) and make sure it's bytes
        content_file = self.instance._open('fake_file', 'rb')
        self.assertTrue(isinstance(content_file.read(), bytes))
        content_file = self.instance._open('fake_file')
        self.assertTrue(isinstance(content_file.read(), bytes))

        # Now try again in text mode (r or rt)
        content_file = self.instance._open('fake_file', 'r')
        self.assertTrue(isinstance(content_file.read(), str))
        content_file = self.instance._open('fake_file', 'rt')
        self.assertTrue(isinstance(content_file.read(), str))

    @patch('storages.backends.azure_storage.AzureStorage.connection')
    def test_save(self, mock_connection):
        """
        _save() should convert ContentFiles to bytes before calling
        put_blob since Azure only takes bytes
        """
        mock_connection.put_blob.return_value = None

        bytes_file = ContentFile(b'This is a test file')
        text_file = ContentFile('This is a test file')

        for content_file in [bytes_file, text_file]:
            self.instance._save('fake_file', content_file)
            # Make sure put_blob was called with bytes
            mock_connection.put_blob.assert_called_with(
                None,
                'fake_file',
                b'This is a test file',
                'BlockBlob',
                x_ms_blob_content_type=None
            )
