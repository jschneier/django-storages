# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock

import mimetypes
import warnings
from datetime import datetime, timedelta

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.test import TestCase, override_settings
from django.utils import timezone
from google.cloud.exceptions import Conflict, NotFound
from google.cloud.storage.blob import Blob
from google.api_core import exceptions

from storages.backends import gcloud


class GCloudTestCase(TestCase):
    def setUp(self):
        self.bucket_name = 'test_bucket'
        self.filename = 'test_file.txt'

        self.storage = gcloud.GoogleCloudStorage(bucket_name=self.bucket_name)

        self.client_patcher = mock.patch('storages.backends.gcloud.Client')
        self.client_patcher.start()

        self.retry_side_effects = 50 * [
            exceptions.TooManyRequests('possible error'),
            exceptions.InternalServerError('another one'),
            exceptions.ServiceUnavailable('and another'),
            None,
        ]

    def tearDown(self):
        self.client_patcher.stop()


class GCloudStorageTests(GCloudTestCase):

    def test_open_read(self):
        """
        Test opening a file and reading from it
        """
        data = b'This is some test read data.'

        f = self.storage.open(self.filename)
        self.storage._client.bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

        f.blob.download_to_file = lambda tmpfile: tmpfile.write(data)
        self.assertEqual(f.read(), data)

    def test_open_read_num_bytes(self):
        data = b'This is some test read data.'
        num_bytes = 10

        f = self.storage.open(self.filename)
        self.storage._client.bucket.assert_called_with(self.bucket_name)
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
        self.storage.default_acl = 'projectPrivate'

        f = self.storage.open(self.filename, 'wb')
        MockBlob.assert_called_with(self.filename, self.storage._bucket, chunk_size=None)

        f.write(data)
        tmpfile = f._file
        # File data is not actually written until close(), so do that.
        f.close()

        MockBlob().upload_from_file.assert_called_with(
            tmpfile, rewind=True,
            content_type=mimetypes.guess_type(self.filename)[0],
            predefined_acl='projectPrivate')

    def test_save(self):
        data = 'This is some test content.'
        content = ContentFile(data)

        self.storage.save(self.filename, content)

        self.storage._client.bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob().upload_from_file.assert_called_with(
            content, rewind=True, size=len(data), content_type=mimetypes.guess_type(self.filename)[0],
            predefined_acl=None)

    def test_save2(self):
        data = 'This is some test ủⓝï℅ⅆℇ content.'
        filename = 'ủⓝï℅ⅆℇ.txt'
        content = ContentFile(data)

        self.storage.save(filename, content)

        self.storage._client.bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob().upload_from_file.assert_called_with(
            content, rewind=True, size=len(data), content_type=mimetypes.guess_type(filename)[0],
            predefined_acl=None)

    def test_save_with_default_acl(self):
        data = 'This is some test ủⓝï℅ⅆℇ content.'
        filename = 'ủⓝï℅ⅆℇ.txt'
        content = ContentFile(data)

        # ACL Options
        # 'projectPrivate', 'bucketOwnerRead', 'bucketOwnerFullControl',
        # 'private', 'authenticatedRead', 'publicRead', 'publicReadWrite'
        self.storage.default_acl = 'publicRead'

        self.storage.save(filename, content)

        self.storage._client.bucket.assert_called_with(self.bucket_name)
        self.storage._bucket.get_blob().upload_from_file.assert_called_with(
            content, rewind=True, size=len(data), content_type=mimetypes.guess_type(filename)[0],
            predefined_acl='publicRead')

    def test_delete(self):
        self.storage.delete(self.filename)

        self.storage._client.bucket.assert_called_with(self.bucket_name)
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

    def test_exists_no_bucket_auto_create(self):
        # exists('') should return true when auto_create_bucket is configured
        # and bucket already exists
        # exists('') should automatically create the bucket if
        # auto_create_bucket is configured
        self.storage.auto_create_bucket = True
        self.storage._client = mock.MagicMock()
        self.storage._client.create_bucket.side_effect = Conflict('dang')

        self.assertTrue(self.storage.exists(''))

    def test_exists_bucket_auto_create(self):
        # exists('') should automatically create the bucket if
        # auto_create_bucket is configured
        self.storage.auto_create_bucket = True
        self.storage._client = mock.MagicMock()

        self.assertTrue(self.storage.exists(''))
        self.storage._client.create_bucket.assert_called_with(self.bucket_name)

    def test_listdir(self):
        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]
        subdir = ""

        self.storage._bucket = mock.MagicMock()
        blobs, prefixes = [], []
        for name in file_names:
            directory = name.rsplit("/", 1)[0]+"/" if "/" in name else ""
            if directory == subdir:
                blob = mock.MagicMock(spec=Blob)
                blob.name = name.split("/")[-1]
                blobs.append(blob)
            else:
                prefixes.append(directory.split("/")[0]+"/")

        return_value = mock.MagicMock()
        return_value.__iter__ = mock.MagicMock(return_value=iter(blobs))
        return_value.prefixes = prefixes
        self.storage._bucket.list_blobs.return_value = return_value

        dirs, files = self.storage.listdir('')

        self.assertEqual(len(dirs), 2)
        for directory in ["some", "other"]:
            self.assertTrue(directory in dirs,
                            """ "{}" not in directory list "{}".""".format(
                                directory, dirs))

        self.assertEqual(len(files), 2)
        for filename in ["2.txt", "4.txt"]:
            self.assertTrue(filename in files,
                            """ "{}" not in file list "{}".""".format(
                                filename, files))

    def test_listdir_subdir(self):
        file_names = ["some/path/1.txt", "some/2.txt"]
        subdir = "some/"

        self.storage._bucket = mock.MagicMock()
        blobs, prefixes = [], []
        for name in file_names:
            directory = name.rsplit("/", 1)[0] + "/"
            if directory == subdir:
                blob = mock.MagicMock(spec=Blob)
                blob.name = name.split("/")[-1]
                blobs.append(blob)
            else:
                prefixes.append(directory.split(subdir)[1])

        return_value = mock.MagicMock()
        return_value.__iter__ = mock.MagicMock(return_value=iter(blobs))
        return_value.prefixes = prefixes
        self.storage._bucket.list_blobs.return_value = return_value

        dirs, files = self.storage.listdir(subdir)

        self.assertEqual(len(dirs), 1)
        self.assertTrue('path' in dirs,
                        """ "path" not in directory list "{}".""".format(dirs))

        self.assertEqual(len(files), 1)
        self.assertTrue('2.txt' in files,
                        """ "2.txt" not in files list "{}".""".format(files))

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
        naive_date = datetime(2017, 1, 2, 3, 4, 5, 678)
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
        naive_date = datetime(2017, 1, 2, 3, 4, 5, 678)
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
        naive_date = datetime(2017, 1, 2, 3, 4, 5, 678)
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

    def test_url_public_object(self):
        url = 'https://example.com/mah-bukkit/{}'.format(self.filename)
        self.storage.default_acl = 'publicRead'

        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        blob.public_url = url
        blob.generate_signed_url = 'not called'
        self.storage._bucket.blob.return_value = blob

        self.assertEqual(self.storage.url(self.filename), url)
        self.storage._bucket.blob.assert_called_with(self.filename)

    def test_url_not_public_file(self):
        secret_filename = 'secret_file.txt'
        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        generate_signed_url = mock.MagicMock(return_value='http://signed_url')
        blob.public_url = 'http://this_is_public_url'
        blob.generate_signed_url = generate_signed_url
        self.storage._bucket.blob.return_value = blob

        url = self.storage.url(secret_filename)
        self.storage._bucket.blob.assert_called_with(secret_filename)
        self.assertEqual(url, 'http://signed_url')
        blob.generate_signed_url.assert_called_with(timedelta(seconds=86400))

    def test_url_not_public_file_with_custom_expires(self):
        secret_filename = 'secret_file.txt'
        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        generate_signed_url = mock.MagicMock(return_value='http://signed_url')
        blob.generate_signed_url = generate_signed_url
        self.storage._bucket.blob.return_value = blob

        self.storage.expiration = timedelta(seconds=3600)

        url = self.storage.url(secret_filename)
        self.storage._bucket.blob.assert_called_with(secret_filename)
        self.assertEqual(url, 'http://signed_url')
        blob.generate_signed_url.assert_called_with(timedelta(seconds=3600))

    def test_custom_endpoint(self):
        self.storage.custom_endpoint = "https://example.com"

        self.storage.default_acl = 'publicRead'
        url = "{}/{}".format(self.storage.custom_endpoint, self.filename)
        self.assertEqual(self.storage.url(self.filename), url)

        signed_url = 'https://signed_url'
        self.storage.default_acl = 'projectPrivate'
        self.storage._bucket = mock.MagicMock()
        blob = mock.MagicMock()
        generate_signed_url = mock.MagicMock(return_value=signed_url)
        blob.generate_signed_url = generate_signed_url
        self.storage._bucket.blob.return_value = blob
        self.assertEqual(self.storage.url(self.filename), signed_url)

    def test_get_available_name(self):
        self.storage.file_overwrite = True
        self.assertEqual(self.storage.get_available_name(
            self.filename), self.filename)

        self.storage._bucket = mock.MagicMock()
        self.storage._bucket.get_blob.return_value = None
        self.storage.file_overwrite = False
        self.assertEqual(self.storage.get_available_name(
            self.filename), self.filename)
        self.storage._bucket.get_blob.assert_called_with(self.filename)

    def test_get_available_name_unicode(self):
        filename = 'ủⓝï℅ⅆℇ.txt'
        self.assertEqual(self.storage.get_available_name(filename), filename)

    def test_cache_control(self):
        data = 'This is some test content.'
        filename = 'cache_control_file.txt'
        content = ContentFile(data)
        cache_control = 'public, max-age=604800'

        self.storage.cache_control = cache_control
        self.storage.save(filename, content)

        bucket = self.storage.client.bucket(self.bucket_name)
        blob = bucket.get_blob(filename)
        self.assertEqual(blob.cache_control, cache_control)

    def test_location_leading_slash(self):
        msg = (
            "GoogleCloudStorage.location cannot begin with a leading slash. "
            "Found '/'. Use '' instead."
        )
        with self.assertRaises(ImproperlyConfigured, msg=msg):
            gcloud.GoogleCloudStorage(location='/')

    def test_deprecated_autocreate_bucket(self):
        with warnings.catch_warnings(record=True) as w:
            gcloud.GoogleCloudStorage(auto_create_bucket=True)
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        message = (
            "Automatic bucket creation will be removed in version 1.10. It encourages "
            "using overly broad credentials with this library. Either create it before "
            "manually or use one of a myriad of automatic configuration management tools. "
            "Unset GS_AUTO_CREATE_BUCKET (it defaults to False) to silence this warning."
        )
        assert str(w[-1].message) == message

    def test_override_settings(self):
        with override_settings(GS_LOCATION='foo1'):
            storage = gcloud.GoogleCloudStorage()
            self.assertEqual(storage.location, 'foo1')
        with override_settings(GS_LOCATION='foo2'):
            storage = gcloud.GoogleCloudStorage()
            self.assertEqual(storage.location, 'foo2')

    def test_override_class_variable(self):
        class MyStorage1(gcloud.GoogleCloudStorage):
            location = 'foo1'

        storage = MyStorage1()
        self.assertEqual(storage.location, 'foo1')

        class MyStorage2(gcloud.GoogleCloudStorage):
            location = 'foo2'

        storage = MyStorage2()
        self.assertEqual(storage.location, 'foo2')

    def test_override_init_argument(self):
        storage = gcloud.GoogleCloudStorage(location='foo1')
        self.assertEqual(storage.location, 'foo1')
        storage = gcloud.GoogleCloudStorage(location='foo2')
        self.assertEqual(storage.location, 'foo2')

    @mock.patch("storages.backends.gcloud.GoogleCloudFile")
    def test_server_error_fails_request(self, file_mock):
        # Fails as retry is not activated
        data = "Some test data"
        content = ContentFile(data)

        file_mock.return_value.blob.upload_from_file.side_effect = self.retry_side_effects

        with self.assertRaises(exceptions.TooManyRequests):
            for _ in self.retry_side_effects:
                self.storage.save(self.filename, content)

    def test_using_custom_retryable(self):
        class SomeTransientException1(Exception):
            pass

        class SomeTransientException2(Exception):
            pass

        storage = gcloud.GoogleCloudStorage(retry=True, initial_delay=0.01, max_delay=0.02,
                                            retryable=(SomeTransientException1, SomeTransientException2))

        side_effects = [SomeTransientException1, SomeTransientException2] * 2
        side_effects.append(None)

        bucket_mock = mock.MagicMock()
        get_blob_mock = mock.MagicMock(side_effect=side_effects)
        bucket_mock.get_blob = storage.retry_handler(get_blob_mock)
        storage._bucket = bucket_mock

        storage.exists(self.filename)

        self.assertEqual(get_blob_mock.call_count, 5)

    @mock.patch("storages.backends.gcloud.Client.return_value")
    def test_complete_failed_request_file(self, client_mock):
        storage = gcloud.GoogleCloudStorage(retry=True, initial_delay=0.01, max_delay=0.02)
        data = "Some test data"
        content = ContentFile(data)

        bucket_mock = client_mock.bucket.return_value
        delete_blob_mock = bucket_mock.delete_blob
        blob_mock = bucket_mock.get_blob.return_value
        upload_mock = blob_mock.upload_from_file
        download_mock = blob_mock.download_to_file

        delete_blob_mock.side_effect = self.retry_side_effects
        upload_mock.side_effect = self.retry_side_effects
        download_mock.side_effect = self.retry_side_effects

        gfile = gcloud.GoogleCloudFile(self.filename, 'rw', storage)
        gfile.read()
        gfile.write(content)
        gfile.close()

        storage.open(self.filename)
        storage.save(self.filename, content)
        storage.delete(self.filename)

        self.assertEqual(upload_mock.call_count, 8)
        self.assertEqual(download_mock.call_count, 4)
        self.assertEqual(delete_blob_mock.call_count, 4)

    @mock.patch("storages.backends.gcloud.Client.return_value")
    def test_complete_failed_request_file_info(self, client_mock):
        storage = gcloud.GoogleCloudStorage(retry=True, initial_delay=0.01, max_delay=0.02)

        get_blob_mock = mock.MagicMock(side_effect=self.retry_side_effects)
        client_mock.bucket.return_value.get_blob = get_blob_mock

        with self.assertRaises(NotFound):
            storage.size(self.filename)
            storage.modified_time(self.filename)
            storage.get_modified_time(self.filename)
            storage.get_created_time(self.filename)
            storage.exists(self.filename)

    @mock.patch("storages.backends.gcloud.Client.return_value")
    def test_complete_failed_request_bucket_managing(self, client_mock):
        storage = gcloud.GoogleCloudStorage(retry=True, initial_delay=0.01, max_delay=0.02, auto_create_bucket=True)

        # "None" from the original list isn't acceptable here
        local_side_effects = self.retry_side_effects[:4]
        local_side_effects[-1] = mock.MagicMock()

        create_mock = client_mock.create_bucket
        create_mock.side_effects = local_side_effects
        get_mock = client_mock.get_bucket
        get_mock.side_effects = local_side_effects

        storage.exists(None)

        create_mock.assert_called_once()
        get_mock.assert_called_once()

    @mock.patch.object(gcloud.GoogleCloudStorage, "_get_blobs")
    def test_complete_failed_request_dirs(self, get_blobs_mock):
        storage = gcloud.GoogleCloudStorage(retry=True, initial_delay=0.01, max_delay=0.02)

        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]
        subdir = ""

        blobs, prefixes = [], []
        for name in file_names:
            directory = name.rsplit("/", 1)[0] + "/" if "/" in name else ""
            if directory == subdir:
                blob = mock.MagicMock(spec=Blob)
                blob.name = name.split("/")[-1]
                blobs.append(blob)
            else:
                prefixes.append(directory.split("/")[0] + "/")

        return_value = [prefixes, blobs]
        side_effects = self.retry_side_effects[:3]
        side_effects.append(return_value)
        get_blobs_mock.side_effect = side_effects

        dirs, files = storage.listdir(subdir)

        self.assertEqual(len(files), 2)
        self.assertEqual(len(dirs), 2)
        self.assertEqual(get_blobs_mock.call_count, 4)
