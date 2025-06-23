import os
import pytest
pytest.importorskip("libcloud")
if not os.environ.get("DJANGO_SETTINGS_MODULE"):
    pytest.skip("DJANGO_SETTINGS_MODULE not set", allow_module_level=True)
from unittest import mock

from django.test import TestCase, override_settings

from storages.backends.apache_libcloud import LibCloudStorage
from storages.utils import clean_name


class MockObject:
    def __init__(self, name):
        self.name = name
        self.size = 1000


class MockDriver:
    def __init__(self):
        self.connection = mock.MagicMock()
        self.connection.host = 'example.com'

    def get_container(self, container_name):
        return mock.MagicMock(name=container_name)

    def get_object(self, container_name, object_name):
        if not object_name:
            from libcloud.storage.types import ObjectDoesNotExistError
            raise ObjectDoesNotExistError('Empty object name', None, None)
        return MockObject(object_name)

    def get_object_cdn_url(self, obj):
        raise NotImplementedError()


class MockCDNDriver(MockDriver):
    def get_object_cdn_url(self, obj):
        return f'https://cdn.example.com/{obj.name}'


LIBCLOUD_PROVIDERS = {
    's3': {
        'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'google': {
        'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'azure': {
        'type': 'libcloud.storage.types.Provider.AZURE_BLOBS',
        'user': 'testuser',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'backblaze': {
        'type': 'libcloud.storage.types.Provider.BACKBLAZE_S3',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'unknown': {
        'type': 'libcloud.storage.types.Provider.UNKNOWN',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
}


@override_settings(LIBCLOUD_PROVIDERS=LIBCLOUD_PROVIDERS)
class LibCloudStorageTests(TestCase):
    def setUp(self):
        self.patcher = mock.patch('storages.backends.apache_libcloud.get_driver')
        self.mock_get_driver = self.patcher.start()
        self.mock_get_driver.return_value = lambda *args, **kwargs: MockDriver()

    def tearDown(self):
        self.patcher.stop()

    def test_url_with_empty_name_s3(self):
        """Test url() with empty name for S3 provider (#133)."""
        storage = LibCloudStorage('s3')
        url = storage.url('')
        self.assertEqual(url, 'https://example.com/test-bucket')

    def test_url_with_empty_name_google(self):
        """Test url() with empty name for Google Storage provider (#133)."""
        storage = LibCloudStorage('google')
        url = storage.url('')
        self.assertEqual(url, 'https://storage.googleapis.com/test-bucket')

    def test_url_with_empty_name_azure(self):
        """Test url() with empty name for Azure provider (#133)."""
        storage = LibCloudStorage('azure')
        url = storage.url('')
        self.assertEqual(url, 'https://testuser.blob.core.windows.net/test-bucket')

    def test_url_with_empty_name_backblaze(self):
        """Test url() with empty name for Backblaze provider (#133)."""
        storage = LibCloudStorage('backblaze')
        url = storage.url('')
        self.assertEqual(url, 'api.backblaze.com/b2api/v1/test-bucket')

    def test_url_with_regular_name(self):
        """Test url() with a regular file name."""
        storage = LibCloudStorage('google')
        url = storage.url('test.jpg')
        self.assertEqual(url, 'https://storage.googleapis.com/test-bucket/test.jpg')

    def test_url_with_cdn_driver(self):
        """Test url() with a CDN-enabled driver."""
        self.mock_get_driver.return_value = lambda *args, **kwargs: MockCDNDriver()
        storage = LibCloudStorage('google')
        url = storage.url('test.jpg')
        self.assertEqual(url, 'https://cdn.example.com/test.jpg')

    def test_url_with_nonexistent_object_cdn(self):
        """Test url() with a nonexistent object with CDN driver."""
        # Make get_object raise ObjectDoesNotExistError
        driver = MockCDNDriver()
        driver.get_object = lambda container, name: None
        self.mock_get_driver.return_value = lambda *args, **kwargs: driver

        storage = LibCloudStorage('google')
        url = storage.url('nonexistent.jpg')
        self.assertIsNone(url)

    def test_clean_name_empty(self):
        """Test clean_name preserves empty string (#132)."""
        self.assertEqual(clean_name(''), '')

    def test_clean_name_dot(self):
        """Test clean_name handles single dot correctly."""
        self.assertEqual(clean_name('.'), '')

    def test_clean_name_with_path(self):
        """Test clean_name with a path."""
        self.assertEqual(clean_name('path/to/file.jpg'), 'path/to/file.jpg')

    def test_unknown_provider_fallback(self):
        """Test fallback to get_object_cdn_url for unknown provider."""
        with self.assertRaises(NotImplementedError):
            storage = LibCloudStorage('unknown')
            storage.url('test.jpg')
from django.test import TestCase, override_settings

from storages.backends.apache_libcloud import LibCloudStorage


class MockDriver:
    def __init__(self, supports_cdn_url=False):
        self.connection = mock.MagicMock()
        self.connection.host = 'example.com'
        self.supports_cdn_url = supports_cdn_url

    def get_container(self, container_name):
        return {'name': container_name}

    def get_object(self, container_name, object_name):
        obj = mock.MagicMock()
        obj.name = object_name
        return obj

    def get_object_cdn_url(self, obj):
        if self.supports_cdn_url:
            return f'https://cdn.example.com/{obj.name}'
        raise NotImplementedError()


LIBCLOUD_PROVIDERS = {
    's3': {
        'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'google': {
        'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'azure': {
        'type': 'libcloud.storage.types.Provider.AZURE_BLOBS',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'backblaze': {
        'type': 'libcloud.storage.types.Provider.BACKBLAZE_S3',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
    'unknown': {
        'type': 'libcloud.storage.types.Provider.UNKNOWN',
        'user': 'test',
        'key': 'test',
        'bucket': 'test-bucket',
    },
}


@override_settings(LIBCLOUD_PROVIDERS=LIBCLOUD_PROVIDERS)
class LibCloudStorageTests(TestCase):
    def setUp(self):
        self.patcher = mock.patch('storages.backends.apache_libcloud.get_driver')
        self.mock_get_driver = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_url_with_cdn_support(self):
        # Test when the driver supports get_object_cdn_url
        mock_driver = MockDriver(supports_cdn_url=True)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('s3')
        url = storage.url('test-file.txt')

        # Should use the CDN URL
        self.assertEqual(url, 'https://cdn.example.com/test-file.txt')

    def test_url_s3_provider(self):
        # Test S3 provider without CDN support
        mock_driver = MockDriver(supports_cdn_url=False)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('s3')
        url = storage.url('test-file.txt')

        # Should construct the URL manually
        self.assertEqual(url, 'https://example.com/test-bucket/test-file.txt')

    def test_url_google_provider(self):
        # Test Google provider
        mock_driver = MockDriver(supports_cdn_url=False)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('google')
        url = storage.url('test-file.txt')

        # Should construct the URL manually
        self.assertEqual(url, 'https://storage.googleapis.com/test-bucket/test-file.txt')

    def test_url_azure_provider(self):
        # Test Azure provider
        mock_driver = MockDriver(supports_cdn_url=False)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('azure')
        url = storage.url('test-file.txt')

        # Should construct the URL manually
        self.assertEqual(url, 'https://test.blob.core.windows.net/test-bucket/test-file.txt')

    def test_url_backblaze_provider(self):
        # Test Backblaze provider
        mock_driver = MockDriver(supports_cdn_url=False)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('backblaze')
        url = storage.url('test-file.txt')

        # Should construct the URL manually
        self.assertEqual(url, 'api.backblaze.com/b2api/v1/test-bucket/test-file.txt')

    def test_url_unknown_provider(self):
        # Test unknown provider
        mock_driver = MockDriver(supports_cdn_url=False)
        self.mock_get_driver.return_value = lambda *args, **kwargs: mock_driver

        storage = LibCloudStorage('unknown')

        # Should raise NotImplementedError
        with self.assertRaises(NotImplementedError):
            storage.url('test-file.txt')