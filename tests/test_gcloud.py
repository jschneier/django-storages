# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock

import datetime
import mimetypes

from django.core.files.base import ContentFile
from django.test import TestCase
from django.utils import timezone
from google.cloud.exceptions import NotFound
from google.cloud.storage.blob import Blob

from storages.backends import gcloud


class GCloudTestCase(TestCase):
    def setUp(self):
        self.bucket_name = 'test_bucket'
        self.filename = 'test_file.txt'

        self.storage = gcloud.GoogleCloudStorage(bucket_name=self.bucket_name)

        self.client_patcher = mock.patch('storages.backends.gcloud.Client')
        self.client_patcher.start()

    def tearDown(self):
        self.client_patcher.stop()


class GCloudStorageTests(GCloudTestCase):

    def test_open_read(self):
        """
        Test opening a file and reading from it
        """
        data = b'This is some test read data.'

        f = self.storage.open(self.filename)
        self.storage._client.get_bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

        f.blob.download_to_file = lambda tmpfile: tmpfile.write(data)
        self.assertEqual(f.read(), data)

    def test_open_read_num_bytes(self):
        data = b'This is some test read data.'
        num_bytes = 10

        f = self.storage.open(self.filename)
        self.storage._client.get_bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

        f.blob.download_to_file = lambda tmpfile: tmpfile.write(data)
        self.assertEqual(f.read(num_bytes), data[0:num_bytes])

    def test_open_read_nonexistent(self):
        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        self.assertRaises(IOError, self.storage.open, self.filename)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_open_read_nonexistent_unicode(self):
        filename = 'ủⓝï℅ⅆℇ.txt'

        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        self.assertRaises(IOError, self.storage.open, filename)

    @mock.patch('storages.backends.gcloud.Blob')
    def test_open_write(self, MockBlob):
        """
        Test opening a file and writing to it
        """
        data = 'This is some test write data.'

        # Simulate the file not existing before the write
        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        f = self.storage.open(self.filename, 'wb')
        MockBlob.assert_called_with(self.filename, self.storage._bucket)

        f.write(data)
        tmpfile = f._file
        # File data is not actually written until close(), so do that.
        f.close()

        MockBlob().upload_from_file.assert_called_with(
            tmpfile, content_type=mimetypes.guess_type(self.filename)[0])

    def test_save(self):
        data = 'This is some test content.'
        content = ContentFile(data)

        self.storage.save(self.filename, content)

        self.storage._client.get_bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob().upload_from_file.assert_called_with(
            content, size=len(data), content_type=mimetypes.guess_type(self.filename)[0])

    def test_save2(self):
        data = 'This is some test ủⓝï℅ⅆℇ content.'
        filename = 'ủⓝï℅ⅆℇ.txt'
        content = ContentFile(data)

        self.storage.save(filename, content)

        self.storage._client.get_bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob().upload_from_file.assert_called_with(
            content, size=len(data), content_type=mimetypes.guess_type(filename)[0])

    def test_delete(self):
        self.storage.delete(self.filename)

        self.storage._client.get_bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.delete_blob.assert_called_with(self.filename)

    def test_exists(self):
        self.storage._bucket = mock.MagicMock()
        self.assertTrue(self.storage.exists(self.filename))
        self.storage._bucket.get_blob.assert_called_with(self.filename)

        self.storage._bucket.reset_mock()
        self.storage._bucket.get_blob.return_value = None
        self.assertFalse(self.storage.exists(self.filename))
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_exists_no_bucket(self):
        # exists('') should return False if the bucket doesn't exist
        self.storage._client = mock.MagicMock()
        self.storage._client.get_bucket.side_effect = NotFound('dang')
        self.assertFalse(self.storage.exists(''))

    def test_exists_bucket(self):
        # exists('') should return True if the bucket exists
        self.assertTrue(self.storage.exists(''))

    def test_exists_bucket_auto_create(self):
        # exists('') should automatically create the bucket if
        # auto_create_bucket is configured
        self.storage.auto_create_bucket = True
        self.storage._client = mock.MagicMock()
        self.storage._client.get_bucket.side_effect = NotFound('dang')

        self.assertTrue(self.storage.exists(''))
        self.storage._client.create_bucket.assert_called_with(self.bucket_name)

    def test_listdir(self):
        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]

        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.list_blobs.return_value = []
        for name in file_names:
            blob = mock.MagicMock(spec=Blob)
            blob.name = name
            self.storage._bucket.list_blobs.return_value.append(blob)

        dirs, files = self.storage.listdir('')

        self.assertEqual(len(dirs), 2)
        for directory in ["some", "other"]:
            self.assertTrue(directory in dirs,
                            """ "%s" not in directory list "%s".""" % (
                                directory, dirs))

        self.assertEqual(len(files), 2)
        for filename in ["2.txt", "4.txt"]:
            self.assertTrue(filename in files,
                            """ "%s" not in file list "%s".""" % (
                                filename, files))

    def test_listdir_subdir(self):
        file_names = ["some/path/1.txt", "some/2.txt"]

        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.list_blobs.return_value = []
        for name in file_names:
            blob = mock.MagicMock(spec=Blob)
            blob.name = name
            self.storage._bucket.list_blobs.return_value.append(blob)

        dirs, files = self.storage.listdir('some/')

        self.assertEqual(len(dirs), 1)
        self.assertTrue('path' in dirs,
                        """ "path" not in directory list "%s".""" % (dirs,))

        self.assertEqual(len(files), 1)
        self.assertTrue('2.txt' in files,
                        """ "2.txt" not in files list "%s".""" % (files,))

    def test_size(self):
        size = 1234

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.size = size
        self.storage._bucket.get_blob.return_value = blob

        self.assertEqual(self.storage.size(self.filename), size)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_size_no_file(self):
        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        self.assertRaises(NotFound, self.storage.size, self.filename)

    def test_modified_time(self):
        naive_date = datetime.datetime(2017, 1, 2, 3, 4, 5, 678)
        aware_date = timezone.make_aware(naive_date, timezone.utc)

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.updated = aware_date
        self.storage._bucket.get_blob.return_value = blob

        with self.settings(TIME_ZONE='UTC'):
            mt = self.storage.modified_time(self.filename)
            self.assertTrue(timezone.is_naive(mt))
            self.assertEqual(mt, naive_date)
            self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_get_modified_time(self):
        naive_date = datetime.datetime(2017, 1, 2, 3, 4, 5, 678)
        aware_date = timezone.make_aware(naive_date, timezone.utc)

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.updated = aware_date
        self.storage._bucket.get_blob.return_value = blob

        with self.settings(TIME_ZONE='America/Montreal', USE_TZ=False):
            mt = self.storage.get_modified_time(self.filename)
            self.assertTrue(timezone.is_naive(mt))
            naive_date_montreal = timezone.make_naive(aware_date)
            self.assertEqual(mt, naive_date_montreal)
            self.storage._bucket.get_blob.assert_called_with(self.filename)

        with self.settings(TIME_ZONE='America/Montreal', USE_TZ=True):
            mt = self.storage.get_modified_time(self.filename)
            self.assertTrue(timezone.is_aware(mt))
            self.assertEqual(mt, aware_date)
            self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_get_created_time(self):
        naive_date = datetime.datetime(2017, 1, 2, 3, 4, 5, 678)
        aware_date = timezone.make_aware(naive_date, timezone.utc)

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.time_created = aware_date
        self.storage._bucket.get_blob.return_value = blob

        with self.settings(TIME_ZONE='America/Montreal', USE_TZ=False):
            mt = self.storage.get_created_time(self.filename)
            self.assertTrue(timezone.is_naive(mt))
            naive_date_montreal = timezone.make_naive(aware_date)
            self.assertEqual(mt, naive_date_montreal)
            self.storage._bucket.get_blob.assert_called_with(self.filename)

        with self.settings(TIME_ZONE='America/Montreal', USE_TZ=True):
            mt = self.storage.get_created_time(self.filename)
            self.assertTrue(timezone.is_aware(mt))
            self.assertEqual(mt, aware_date)
            self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_modified_time_no_file(self):
        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        self.assertRaises(NotFound, self.storage.modified_time, self.filename)

    def test_url(self):
        url = 'https://example.com/mah-bukkit/{}'.format(self.filename)

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.public_url = url
        self.storage._bucket.get_blob.return_value = blob

        self.assertEqual(self.storage.url(self.filename), url)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_url_no_file(self):
        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None

        self.assertRaises(NotFound, self.storage.url, self.filename)

    def test_get_available_name(self):
        self.storage.file_overwrite = True
        self.assertEqual(self.storage.get_available_name(self.filename), self.filename)

        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None
        self.storage.file_overwrite = False
        self.assertEqual(self.storage.get_available_name(self.filename), self.filename)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_get_available_name_unicode(self):
        filename = 'ủⓝï℅ⅆℇ.txt'
        self.assertEqual(self.storage.get_available_name(filename), filename)
