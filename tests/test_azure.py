import datetime
from datetime import timedelta
from unittest import mock

import django
from azure.storage.blob import BlobProperties
from django.core.exceptions import SuspiciousOperation
from django.core.files.base import ContentFile
from django.test import TestCase
from django.test import override_settings
from django.utils.timezone import make_aware

from storages.backends import azure_storage


class AzureStorageTest(TestCase):
    def setUp(self, *args):
        self.storage = azure_storage.AzureStorage()
        self.storage._client = mock.MagicMock()
        self.storage.overwrite_files = True
        self.account_name = "test"
        self.account_key = "key"
        self.container_name = "test"
        self.storage.azure_account = self.account_name
        self.storage.account_key = self.account_key
        self.storage.azure_container = self.container_name

    def test_get_valid_path(self):
        self.assertEqual(
            self.storage._get_valid_path("path/to/somewhere"), "path/to/somewhere"
        )
        self.assertEqual(
            self.storage._get_valid_path("path/to/../somewhere"), "path/somewhere"
        )
        self.assertEqual(self.storage._get_valid_path("path/to/../"), "path")
        self.assertEqual(self.storage._get_valid_path("path\\to\\..\\"), "path")
        self.assertEqual(self.storage._get_valid_path("path/name/"), "path/name")
        self.assertEqual(
            self.storage._get_valid_path("path\\to\\somewhere"), "path/to/somewhere"
        )
        self.assertEqual(self.storage._get_valid_path("some/$/path"), "some/$/path")
        self.assertEqual(self.storage._get_valid_path("/$/path"), "$/path")
        self.assertEqual(self.storage._get_valid_path("path/$/"), "path/$")
        self.assertEqual(
            self.storage._get_valid_path("path/$/$/$/path"), "path/$/$/$/path"
        )
        self.assertEqual(self.storage._get_valid_path("some///path"), "some/path")
        self.assertEqual(self.storage._get_valid_path("some//path"), "some/path")
        self.assertEqual(self.storage._get_valid_path("some\\\\path"), "some/path")
        self.assertEqual(self.storage._get_valid_path("a" * 1024), "a" * 1024)
        self.assertEqual(self.storage._get_valid_path("a/a" * 256), "a/a" * 256)
        self.assertRaises(ValueError, self.storage._get_valid_path, "")
        self.assertRaises(ValueError, self.storage._get_valid_path, "/")
        self.assertRaises(ValueError, self.storage._get_valid_path, "/../")
        self.assertRaises(ValueError, self.storage._get_valid_path, "..")
        self.assertRaises(ValueError, self.storage._get_valid_path, "///")
        self.assertRaises(ValueError, self.storage._get_valid_path, "a" * 1025)
        self.assertRaises(ValueError, self.storage._get_valid_path, "a/a" * 257)

    def test_get_valid_path_idempotency(self):
        self.assertEqual(self.storage._get_valid_path("//$//a//$//"), "$/a/$")
        self.assertEqual(
            self.storage._get_valid_path(self.storage._get_valid_path("//$//a//$//")),
            self.storage._get_valid_path("//$//a//$//"),
        )
        some_path = "some path/some long name & then some.txt"
        self.assertEqual(self.storage._get_valid_path(some_path), some_path)
        self.assertEqual(
            self.storage._get_valid_path(self.storage._get_valid_path(some_path)),
            self.storage._get_valid_path(some_path),
        )

    def test_get_available_name(self):
        self.storage.overwrite_files = False
        client_mock = mock.MagicMock()
        client_mock.exists.side_effect = [True, False]
        self.storage._client.get_blob_client.return_value = client_mock
        name = self.storage.get_available_name("foo.txt")
        self.assertTrue(name.startswith("foo_"))
        self.assertTrue(name.endswith(".txt"))
        self.assertTrue(len(name) > len("foo.txt"))
        self.assertEqual(client_mock.exists.call_count, 2)

    def test_get_available_name_first(self):
        self.storage.overwrite_files = False
        client_mock = mock.MagicMock()
        client_mock.exists.return_value = False
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertEqual(
            self.storage.get_available_name("foo bar baz.txt"), "foo bar baz.txt"
        )
        self.assertEqual(client_mock.exists.call_count, 1)

    def test_get_available_name_max_len(self):
        self.storage.overwrite_files = False
        # if you wonder why this is, file-system
        # storage will raise when file name is too long as well,
        # the form should validate this
        client_mock = mock.MagicMock()
        client_mock.exists.side_effect = [True, False]
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertRaises(ValueError, self.storage.get_available_name, "a" * 1025)
        name = self.storage.get_available_name(
            "a" * 1000, max_length=100
        )  # max_len == 1024
        self.assertEqual(len(name), 100)
        self.assertTrue("_" in name)
        self.assertEqual(client_mock.exists.call_count, 2)

    def test_get_available_invalid(self):
        self.storage.overwrite_files = False
        self.storage._client.exists.return_value = False
        if django.VERSION[:2] == (3, 0):
            # Django 2.2.21 added this security fix:
            # https://docs.djangoproject.com/en/3.2/releases/2.2.21/#cve-2021-31542-potential-directory-traversal-via-uploaded-files
            # It raises SuspiciousOperation before we get to our ValueError.
            # The fix wasn't applied to 3.0 (no longer in support), but was applied to
            # 3.1 & 3.2.
            self.assertRaises(ValueError, self.storage.get_available_name, "")
            self.assertRaises(ValueError, self.storage.get_available_name, "/")
            self.assertRaises(ValueError, self.storage.get_available_name, ".")
            self.assertRaises(ValueError, self.storage.get_available_name, "///")
        else:
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, "")
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, "/")
            self.assertRaises(SuspiciousOperation, self.storage.get_available_name, ".")
            self.assertRaises(
                SuspiciousOperation, self.storage.get_available_name, "///"
            )
        self.assertRaises(ValueError, self.storage.get_available_name, "...")

    def test_url(self):
        blob_mock = mock.MagicMock()
        blob_mock.url = "https://ret_foo.blob.core.windows.net/test/some%20blob"
        self.storage._client.get_blob_client.return_value = blob_mock
        self.assertEqual(self.storage.url("some blob"), blob_mock.url)
        self.storage._client.get_blob_client.assert_called_once_with("some blob")

    def test_url_unsafe_chars(self):
        blob_mock = mock.MagicMock()
        blob_mock.url = "https://ret_foo.blob.core.windows.net/test/some%20blob"
        self.storage._client.get_blob_client.return_value = blob_mock
        self.assertEqual(
            self.storage.url("foo;?:@=&\"<>#%{}|^~[]`bar/~!*()'"), blob_mock.url
        )
        self.storage._client.get_blob_client.assert_called_once_with(
            "foo;?:@=&\"<>#%{}|^~[]`bar/~!*()'"
        )

    @mock.patch("storages.backends.azure_storage.generate_blob_sas")
    def test_url_expire(self, generate_blob_sas_mocked):
        generate_blob_sas_mocked.return_value = "foo_token"
        blob_mock = mock.MagicMock()
        blob_mock.url = "https://ret_foo.blob.core.windows.net/test/some%20blob"
        self.storage._client.get_blob_client.return_value = blob_mock
        self.storage.account_name = self.account_name

        fixed_time = make_aware(
            datetime.datetime(2016, 11, 6, 4), datetime.timezone.utc
        )

        with mock.patch("storages.backends.azure_storage.datetime") as d_mocked:
            # Implicit read permission
            d_mocked.utcnow.return_value = fixed_time
            self.assertEqual(
                self.storage.url("some blob", 100),
                "https://ret_foo.blob.core.windows.net/test/some%20blob",
            )
            generate_blob_sas_mocked.assert_called_once_with(
                self.account_name,
                self.container_name,
                "some blob",
                account_key=self.account_key,
                user_delegation_key=None,
                permission=mock.ANY,
                expiry=fixed_time + timedelta(seconds=100),
            )
            called_args, called_kwargs = generate_blob_sas_mocked.call_args
            self.assertEqual(str(called_kwargs["permission"]), "r")

            # Explicit write permission
            d_mocked.utcnow.return_value = fixed_time
            self.assertEqual(
                self.storage.url("some blob", expire=100, mode="w"),
                "https://ret_foo.blob.core.windows.net/test/some%20blob",
            )
            generate_blob_sas_mocked.assert_called_with(
                self.account_name,
                self.container_name,
                "some blob",
                account_key=self.account_key,
                user_delegation_key=None,
                permission=mock.ANY,
                expiry=fixed_time + timedelta(seconds=100),
            )
            called_args, called_kwargs = generate_blob_sas_mocked.call_args
            self.assertEqual(str(called_kwargs["permission"]), "w")

    def test_url_custom_domain(self):
        self.storage.custom_domain = "foo_domain"
        blob_mock = mock.MagicMock()
        blob_mock.url = "https://ret_foo.blob.core.windows.net/test/foo_name"
        self.storage._client.get_blob_client.return_value = blob_mock
        url = self.storage.url("foo_name")
        self.assertEqual(url, "https://foo_domain/test/foo_name")

    @mock.patch("storages.backends.azure_storage.generate_blob_sas")
    def test_url_expire_user_delegation_key(self, generate_blob_sas_mocked):
        generate_blob_sas_mocked.return_value = "foo_token"
        blob_mock = mock.MagicMock()
        blob_mock.url = "https://ret_foo.blob.core.windows.net/test/some%20blob"
        self.storage._client.get_blob_client.return_value = blob_mock
        self.storage.account_name = self.account_name
        service_client = mock.MagicMock()
        self.storage._service_client = service_client
        self.storage.token_credential = "token_credential"

        fixed_time = make_aware(
            datetime.datetime(2016, 11, 6, 4), datetime.timezone.utc
        )
        with mock.patch("storages.backends.azure_storage.datetime") as d_mocked:
            d_mocked.utcnow.return_value = fixed_time
            service_client.get_user_delegation_key.return_value = "user delegation key"
            self.assertEqual(
                self.storage.url("some blob", 100),
                "https://ret_foo.blob.core.windows.net/test/some%20blob",
            )
            generate_blob_sas_mocked.assert_called_once_with(
                self.account_name,
                self.container_name,
                "some blob",
                account_key=self.account_key,
                user_delegation_key="user delegation key",
                permission=mock.ANY,
                expiry=fixed_time + timedelta(seconds=100),
            )

    def test_container_client_default_params(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = self.account_name
        with mock.patch(
            "storages.backends.azure_storage.BlobServiceClient", autospec=True
        ) as bsc_mocked:
            client_mock = mock.MagicMock()
            bsc_mocked.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc_mocked.assert_called_once_with(
                "https://test.blob.core.windows.net", credential=None
            )

    def test_container_client_params_account_key(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = "foo_name"
        storage.custom_domain = "foo_domain"
        storage.account_key = "foo_key"
        with mock.patch(
            "storages.backends.azure_storage.BlobServiceClient", autospec=True
        ) as bsc_mocked:
            client_mock = mock.MagicMock()
            bsc_mocked.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc_mocked.assert_called_once_with(
                "https://foo_name.blob.core.windows.net",
                credential={"account_name": "foo_name", "account_key": "foo_key"},
            )

    def test_container_client_params_sas_token(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = "foo_name"
        storage.azure_ssl = False
        storage.sas_token = "foo_token"
        with mock.patch(
            "storages.backends.azure_storage.BlobServiceClient", autospec=True
        ) as bsc_mocked:
            client_mock = mock.MagicMock()
            bsc_mocked.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc_mocked.assert_called_once_with(
                "http://foo_name.blob.core.windows.net", credential="foo_token"
            )

    def test_container_client_params_token_credential(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = self.account_name
        storage.token_credential = "foo_cred"
        with mock.patch(
            "storages.backends.azure_storage.BlobServiceClient", autospec=True
        ) as bsc_mocked:
            client_mock = mock.MagicMock()
            bsc_mocked.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc_mocked.assert_called_once_with(
                "https://test.blob.core.windows.net", credential="foo_cred"
            )

    def test_connection_string_can_have_missing(self):
        storage = azure_storage.AzureStorage(
            connection_string="AccountKey=abc;Foobar=xyz;"
        )
        self.assertEqual(storage.account_key, "abc")
        self.assertIsNone(storage.account_name)

    def test_container_client_params_connection_string(self):
        storage = azure_storage.AzureStorage()
        storage.account_name = self.account_name
        storage.connection_string = "foo_conn"
        with mock.patch(
            "storages.backends.azure_storage.BlobServiceClient.from_connection_string",
            spec=azure_storage.BlobServiceClient.from_connection_string,
        ) as bsc_mocked:
            client_mock = mock.MagicMock()
            bsc_mocked.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc_mocked.assert_called_once_with("foo_conn")

    # From boto3

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = "test storage save.txt"
        content = ContentFile("new content")
        with mock.patch("storages.backends.azure_storage.ContentSettings") as c_mocked:
            c_mocked.return_value = "content_settings_foo"
            self.assertEqual(self.storage.save(name, content), name)
            self.storage._client.upload_blob.assert_called_once_with(
                name,
                content.file,
                content_settings="content_settings_foo",
                max_concurrency=2,
                timeout=20,
                overwrite=True,
            )
            c_mocked.assert_called_once_with(
                content_type="text/plain", content_encoding=None, cache_control=None
            )

    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = "test_open_for_writïng.txt"
        content = "new content"

        file = self.storage.open(name, "w")
        file.write(content)
        written_file = file.file
        file.close()
        self.storage._client.upload_blob.assert_called_once_with(
            name,
            written_file,
            content_settings=mock.ANY,
            max_concurrency=2,
            timeout=20,
            overwrite=True,
        )

    def test_storage_exists(self):
        blob_name = "blob"
        client_mock = mock.MagicMock()
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertTrue(self.storage.exists(blob_name))
        self.assertEqual(client_mock.exists.call_count, 1)

    def test_delete_blob(self):
        self.storage.delete("name")
        self.storage._client.delete_blob.assert_called_once_with("name", timeout=20)

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
            name_starts_with="", timeout=20
        )
        self.assertEqual(len(dirs), 0)

        self.assertEqual(len(files), 4)
        for filename in ["2.txt", "4.txt", "other/path/3.txt", "some/path/1.txt"]:
            self.assertTrue(
                filename in files,
                """ "{}" not in file list "{}".""".format(filename, files),
            )

    def test_size_of_file(self):
        props = BlobProperties()
        props.size = 12
        client_mock = mock.MagicMock()
        client_mock.get_blob_properties.return_value = props
        self.storage._client.get_blob_client.return_value = client_mock
        self.assertEqual(12, self.storage.size("name"))

    def test_override_settings(self):
        with override_settings(AZURE_CONTAINER="foo1"):
            storage = azure_storage.AzureStorage()
            self.assertEqual(storage.azure_container, "foo1")
        with override_settings(AZURE_CONTAINER="foo2"):
            storage = azure_storage.AzureStorage()
            self.assertEqual(storage.azure_container, "foo2")

    def test_override_class_variable(self):
        class MyStorage1(azure_storage.AzureStorage):
            azure_container = "foo1"

        storage = MyStorage1()
        self.assertEqual(storage.azure_container, "foo1")

        class MyStorage2(azure_storage.AzureStorage):
            azure_container = "foo2"

        storage = MyStorage2()
        self.assertEqual(storage.azure_container, "foo2")

    def test_override_init_argument(self):
        storage = azure_storage.AzureStorage(azure_container="foo1")
        self.assertEqual(storage.azure_container, "foo1")
        storage = azure_storage.AzureStorage(azure_container="foo2")
        self.assertEqual(storage.azure_container, "foo2")

    @mock.patch("storages.backends.azure_storage.BlobServiceClient", autospec=True)
    def test_client_settings(self, bsc):
        with override_settings(AZURE_CLIENT_OPTIONS={"api_version": "1.3"}):
            storage = azure_storage.AzureStorage(account_name="test")
            client_mock = mock.MagicMock()
            bsc.return_value.get_container_client.return_value = client_mock
            self.assertEqual(storage.client, client_mock)
            bsc.assert_called_once_with(
                "https://test.blob.core.windows.net", credential=None, api_version="1.3"
            )
