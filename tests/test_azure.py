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
        self.container_name = 'test'
        self.storage.azure_container = self.container_name

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
        blob_name = "blob_name"
        sent_kwargs = {}

        def mocked_stream(*args, **kwargs):
            stream = kwargs['stream']
            stream.write(mocked_binary)
            sent_kwargs.update(kwargs)

        self.storage.connection.get_blob_to_stream.side_effect = mocked_stream
        with self.storage.open(blob_name, "rb") as f:
            content = f.read()
        self.assertEqual(mocked_binary, content)
        # I am doing this trick here to validate that the method was called, I couldn't use it with
        # the known parameter since a stream is an internal object that I don't have access to
        self.storage.connection.get_blob_to_stream.assert_called_once_with(**sent_kwargs)

    def test_blob_open_write(self):
        mocked_binary = b"written text"
        with self.storage.open("name", "wb") as f:
            f.write(mocked_binary)
            f.close()
        self.storage.connection.create_blob_from_bytes.assert_called_once_with(blob=mocked_binary, blob_name="name",
                                                                               max_connections=2,
                                                                               container_name=self.container_name)

    def test_blob_open_text_write(self):
        mocked_text = "written text"
        with self.storage.open("name", "w") as f:
            f.write(mocked_text)
            f.close()
        self.storage.connection.create_blob_from_text.assert_called_once_with(text=mocked_text, blob_name="name",
                                                                              max_connections=2,
                                                                              container_name=self.container_name)
