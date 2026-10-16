from unittest import mock

from django.test import SimpleTestCase
from libcloud.storage.types import ObjectDoesNotExistError

from storages.backends.apache_libcloud import LibCloudStorage


class LibCloudReadTests(SimpleTestCase):
    def setUp(self):
        self.storage = object.__new__(LibCloudStorage)
        self.storage.driver = mock.Mock()
        self.obj = mock.Mock(size=15)
        self.storage._get_object = mock.Mock(return_value=self.obj)

    def test_read_all_chunks(self):
        self.storage.driver.download_object_as_stream.return_value = iter(
            (b"first", b"second", b"last")
        )
        self.assertEqual(self.storage.open("file.bin").read(), b"firstsecondlast")
        self.storage.driver.download_object_as_stream.assert_called_once_with(
            self.obj, self.obj.size
        )

    def test_read_empty_stream(self):
        self.storage.driver.download_object_as_stream.return_value = iter(())
        self.assertEqual(self.storage.open("empty.bin").read(), b"")

    def test_read_single_chunk(self):
        self.storage.driver.download_object_as_stream.return_value = iter((b"data",))
        self.assertEqual(self.storage.open("small.bin").read(), b"data")

    def test_partial_reads_use_complete_buffer(self):
        self.storage.driver.download_object_as_stream.return_value = iter(
            (b"first", b"second", b"last")
        )
        f = self.storage.open("file.bin")
        self.assertEqual(f.read(7), b"firstse")
        self.assertEqual(f.read(), b"condlast")
        f.seek(0)
        self.assertEqual(f.read(), b"firstsecondlast")
        self.storage.driver.download_object_as_stream.assert_called_once()

    def test_missing_object_raises_file_not_found(self):
        self.storage._get_object.side_effect = ObjectDoesNotExistError(
            "missing", self.storage.driver, "missing.bin"
        )
        with self.assertRaises(FileNotFoundError):
            self.storage.open("missing.bin").read()

    def test_later_stream_error_is_not_silently_truncated(self):
        def chunks():
            yield b"first"
            raise OSError("download interrupted")

        self.storage.driver.download_object_as_stream.return_value = chunks()
        with self.assertRaises(OSError):
            self.storage.open("file.bin").read()
