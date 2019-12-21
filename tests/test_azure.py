import datetime
from datetime import timedelta
from unittest import mock

import django
import pytz
from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobProperties
from django.core.exceptions import SuspiciousOperation
from django.core.files.base import ContentFile
from django.test import TestCase, override_settings

from storages.backends import azure_storage


class AzureStorageTest(TestCase):

    def setUp(self, *args):
        self.storage = azure_storage.AzureStorage()
        self.storage._client = mock.MagicMock()
        self.storage.overwrite_files = True
        self.account_name = 'test'
        self.account_key = 'key'
        self.container_name = 'test'
        self.storage.azure_account = self.account_name
        self.storage.account_key = self.account_key
        self.storage.azure_container = self.container_name

    def test_get_valid_path(self):
        self.assertEqual(
            self.storage._get_valid_path("path/to/somewhere"),
            "path/to/somewhere")
        self.assertEqual(
            self.storage._get_valid_path("path/to/../somewhere"),
            "path/somewhere")
        self.assertEqual(
            self.storage._get_valid_path("path/to/../"), "path")
        self.assertEqual(
            self.storage._get_valid_path("path\\to\\..\\"), "path")
        self.assertEqual(
            self.storage._get_valid_path("path/name/"), "path/name")
        self.assertEqual(
            self.storage._get_valid_path("path\\to\\somewhere"),
            "path/to/somewhere")
        self.assertEqual(
            self.storage._get_valid_path("some/$/path"), "some/$/path")
        self.assertEqual(
            self.storage._get_valid_path("/$/path"), "$/path")
        self.assertEqual(
            self.storage._get_valid_path("path/$/"), "path/$")
        self.assertEqual(
            self.storage._get_valid_path("path/$/$/$/path"), "path/$/$/$/path")
        self.assertEqual(
            self.storage._get_valid_path("some///path"), "some/path")
        self.assertEqual(
            self.storage._get_valid_path("some//path"), "some/path")
        self.assertEqual(
            self.storage._get_valid_path("some\\\\path"), "some/path")
        self.assertEqual(
            self.storage._get_valid_path("a" * 1024), "a" * 1024)
        self.assertEqual(
            self.storage._get_valid_path("a/a" * 256), "a/a" * 256)
        self.assertRaises(ValueError, self.storage._get_valid_path, "")
        self.assertRaises(ValueError, self.storage._get_valid_path, "/")
        self.assertRaises(ValueError, self.storage._get_valid_path, "/../")
        self.assertRaises(ValueError, self.storage._get_valid_path, "..")
        self.assertRaises(ValueError, self.storage._get_valid_path, "///")
        self.assertRaises(ValueError, self.storage._get_valid_path, "a" * 1025)
        self.assertRaises(ValueError, self.storage._get_valid_path, "a/a" * 257)

    def test_get_valid_path_idempotency(self):
        self.assertEqual(
            self.storage._get_valid_path("//$//a//$//"), "$/a/$")
        self.assertEqual(
            self.storage._get_valid_path(
                self.storage._get_valid_path("//$//a//$//")),
            self.storage._get_valid_path("//$//a//$//"))
        some_path = "some path/some long name & then some.txt"
        self.assertEqual(
            self.storage._get_valid_path(some_path), some_path)
        self.assertEqual(
            self.storage._get_valid_path(
                self.storage._get_valid_path(some_path)),
            self.storage._get_valid_path(some_path))

    def test_get_available_name(self):
        self.storage.overwrite_files = False
        client_mock = mock.MagicMock()
        client_mock.get_blob_properties.side_effect = [True, ResourceNotFoundError]
        self.storage._client.get_blob_client.return_value = client_mock
        name = self.storage.get_available_name('foo.txt')
        self.assertTrue(name.startswith('foo_'))
        self.assertTrue(name.endswith('.txt'))
        self.assertTrue(len(name) > len('foo.txt'))
        self.assertEqual(client_mock.get_blob_properties.call_count, 2)

    def test_get_available_name_first(self):
        self.storage.overwrite_files = False
        client_mock = mock.MagicMock()
        client_mock.get_blob_properties.side_effect = [ResourceNotFoundError]
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertEqual(
            self.storage.get_available_name('foo bar baz.txt'),
            'foo bar baz.txt')
        self.assertEqual(client_mock.get_blob_properties.call_count, 1)

    def test_get_available_name_max_len(self):
        self.storage.overwrite_files = False
        # if you wonder why this is, file-system
        # storage will raise when file name is too long as well,
        # the form should validate this
        client_mock = mock.MagicMock()
        client_mock.get_blob_properties.side_effect = [False, ResourceNotFoundError]
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertRaises(ValueError, self.storage.get_available_name, 'a' * 1025)
        name = self.storage.get_available_name('a' * 1000, max_length=100)  # max_len == 1024
        self.assertEqual(len(name), 100)
        self.assertTrue('_' in name)
        self.assertEqual(client_mock.get_blob_properties.call_count, 2)

    def test_get_available_invalid(self):
        self.storage.overwrite_files = False
        self.storage._client.get_blob_properties.return_value = False
        if django.VERSION[:2] == (3, 0):
            # Django 2.2.21 added this security fix:
            # https://docs.djangoproject.com/en/3.2/releases/2.2.21/#cve-2021-31542-potential-directory-traversal-via-uploaded-files
            # It raises SuspiciousOperation before we get to our ValueError.
            # The fix wasn't applied to 3.0 (no longer in support), but was applied to 3.1 & 3.2.
            self.assertRaises(ValueError, self.storage.get_available_name, "")
            self.assertRaises(ValueError, self.storage.get_available_name, "/")
            self.assertRaises(ValueError, self.storage.get_available_name, ".")
            self.assertRaises(ValueError, self.storage.get_available_name, "///")
        else:
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, "")
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, "/")
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, ".")
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, "///")
        self.assertRaises(ValueError, self.storage.get_available_name, "...")

    def test_url(self):
        blob_mock = mock.MagicMock()
        blob_mock.url = 'https://ret_foo.blob.core.windows.net/test/some%20blob'
        self.storage._client.get_blob_client.return_value = blob_mock
        self.assertEqual(self.storage.url('some blob'), blob_mock.url)
        self.storage._client.get_blob_client.assert_called_once_with('some%20blob')

    def test_url_unsafe_chars(self):
        blob_mock = mock.MagicMock()
        blob_mock.url = 'https://ret_foo.blob.core.windows.net/test/some%20blob'
        self.storage._client.get_blob_client.return_value = blob_mock
        self.assertEqual(
            self.storage.url('foo;?:@=&"<>#%{}|^~[]`bar/~!*()\''), blob_mock.url)
        self.storage.client.get_blob_client.assert_called_once_with(
            'foo%3B%3F%3A%40%3D%26%22%3C%3E%23%25%7B%7D%7C%5E~%5B%5D%60bar/~!*()\'')

    @mock.patch('storages.backends.azure_storage.generate_blob_sas')
    def test_url_expire(self, generate_blob_sas_mocked):
        generate_blob_sas_mocked.return_value = 'foo_token'
        blob_mock = mock.MagicMock()
        blob_mock.url = 'https://ret_foo.blob.core.windows.net/test/some%20blob'
        self.storage._client.get_blob_client.return_value = blob_mock
        self.storage.account_name = self.account_name

        utc = pytz.timezone('UTC')
        fixed_time = utc.localize(datetime.datetime(2016, 11, 6, 4))
        with mock.patch('storages.backends.azure_storage.datetime') as d_mocked:
            d_mocked.utcnow.return_value = fixed_time
            self.assertEquals(
                self.storage.url('some blob', 100),
                'https://ret_foo.blob.core.windows.net/test/some%20blob')
            generate_blob_sas_mocked.assert_called_once_with(
                self.account_name,
                self.container_name,
                'some blob',
                account_key=self.account_key,
                permission=mock.ANY,
                expiry=fixed_time + timedelta(seconds=100))

    def test_container_client_default_params(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = self.account_name
        with mock.patch(
                'storages.backends.azure_storage.ContainerClient',
                autospec=True) as c_mocked:
            self.assertIsNotNone(storage.client)
            c_mocked.assert_called_once_with(
                'https://test.blob.core.windows.net',
                None,
                credential=None)

    def test_container_client_params(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = 'foo_name'
        storage.account_key = 'foo_key'
        storage.sas_token = 'foo_token'
        storage.azure_ssl = True
        storage.custom_domain = 'foo_domain'
        storage.connection_string = 'foo_conn'
        storage.token_credential = 'foo_cred'
        with mock.patch(
                'storages.backends.azure_storage.ContainerClient',
                autospec=True) as c_mocked:
            self.assertIsNotNone(storage.client)
            c_mocked.assert_called_once_with(
                'foo_conn',
                None,
                credential='foo_key')

    # From boto3

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = 'test storage save.txt'
        content = ContentFile('new content')
        with mock.patch('storages.backends.azure_storage.ContentSettings') as c_mocked:
            c_mocked.return_value = 'content_settings_foo'
            self.assertEqual(self.storage.save(name, content), name)
            self.storage._client.upload_blob.assert_called_once_with(
                name,
                content.file,
                content_settings='content_settings_foo',
                max_concurrency=2,
                timeout=20,
                overwrite=True)
            c_mocked.assert_called_once_with(
                content_type='text/plain',
                content_encoding=None,
                cache_control=None)

    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = 'test_open_for_writïng.txt'
        content = 'new content'

        file = self.storage.open(name, 'w')
        file.write(content)
        written_file = file.file
        file.close()
        self.storage._client.upload_blob.assert_called_once_with(
            name,
            written_file,
            content_settings=mock.ANY,
            max_concurrency=2,
            timeout=20,
            overwrite=True)

    def test_storage_exists(self):
        blob_name = "blob"
        client_mock = mock.MagicMock()
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertTrue(self.storage.exists(blob_name))
        self.assertEqual(client_mock.get_blob_properties.call_count, 1)

    def test_delete_blob(self):
        self.storage.delete("name")
        self.storage._client.delete_blob.assert_called_once_with(
            "name", timeout=20)

    def test_storage_listdir_base(self):
        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]

        result = []
        for p in file_names:
            obj = mock.MagicMock()
            obj.name = p
            result.append(obj)
        self.storage._client.list_blobs.return_value = iter(result)

        dirs, files = self.storage.listdir("")
        self.storage._client.list_blobs.assert_called_with(
            name_starts_with="", timeout=20)

        self.assertEqual(len(dirs), 2)
        for directory in ["some", "other"]:
            self.assertTrue(
                directory in dirs,
                """ "{}" not in directory list "{}".""".format(directory, dirs))

        self.assertEqual(len(files), 2)
        for filename in ["2.txt", "4.txt"]:
            self.assertTrue(
                filename in files,
                """ "{}" not in file list "{}".""".format(filename, files))

    def test_storage_listdir_subdir(self):
        file_names = ["some/path/1.txt", "some/2.txt"]

        result = []
        for p in file_names:
            obj = mock.MagicMock()
            obj.name = p
            result.append(obj)
        self.storage._client.list_blobs.return_value = iter(result)

        dirs, files = self.storage.listdir("some/")
        self.storage._client.list_blobs.assert_called_with(
            name_starts_with="some/", timeout=20)

        self.assertEqual(len(dirs), 1)
        self.assertTrue(
            'path' in dirs,
            """ "path" not in directory list "{}".""".format(dirs))

        self.assertEqual(len(files), 1)
        self.assertTrue(
            '2.txt' in files,
            """ "2.txt" not in files list "{}".""".format(files))

    def test_size_of_file(self):
        props = BlobProperties()
        props.size = 12
        client_mock = mock.MagicMock()
        client_mock.get_blob_properties.return_value = props
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertEqual(12, self.storage.size("name"))

    def test_last_modified_of_file(self):
        props = BlobProperties()
        accepted_time = datetime.datetime(2017, 5, 11, 8, 52, 4)
        props.last_modified = accepted_time
        self.storage._client.get_blob_properties.return_value = props
        time = self.storage.modified_time("name")
        self.assertEqual(accepted_time, time)

    def test_override_settings(self):
        with override_settings(AZURE_CONTAINER='foo1'):
            storage = azure_storage.AzureStorage()
            self.assertEqual(storage.azure_container, 'foo1')
        with override_settings(AZURE_CONTAINER='foo2'):
            storage = azure_storage.AzureStorage()
            self.assertEqual(storage.azure_container, 'foo2')

    def test_override_class_variable(self):
        class MyStorage1(azure_storage.AzureStorage):
            azure_container = 'foo1'

        storage = MyStorage1()
        self.assertEqual(storage.azure_container, 'foo1')

        class MyStorage2(azure_storage.AzureStorage):
            azure_container = 'foo2'

        storage = MyStorage2()
        self.assertEqual(storage.azure_container, 'foo2')

    def test_override_init_argument(self):
        storage = azure_storage.AzureStorage(azure_container='foo1')
        self.assertEqual(storage.azure_container, 'foo1')
        storage = azure_storage.AzureStorage(azure_container='foo2')
        self.assertEqual(storage.azure_container, 'foo2')
