import os
import sys
import unittest
import pytest
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Check if libcloud is available, otherwise skip this file
try:
    import libcloud
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False
    # Mark the module to be skipped
    pytest.skip("libcloud not installed", allow_module_level=True)
    # Create a mock libcloud module for testing imports
    class MockLibcloud:
        pass
    sys.modules['libcloud'] = MockLibcloud()

# Mock Django settings before importing LibCloudStorage
with patch('django.conf.settings') as mock_settings:
    mock_settings.configured = True
    from storages.backends.apache_libcloud import LibCloudStorage

class MockConnection:
    def __init__(self):
        self.host = 'example.com'

class MockDriver:
    def __init__(self):
        self.connection = MockConnection()

class MockObject:
    def __init__(self, name):
        self.name = name

class LibCloudStorageUrlTest(unittest.TestCase):
    """Tests for LibCloudStorage.url() that can run without full Django settings"""

    def setUp(self):
        # Create a partially mocked LibCloudStorage instance
        with patch.object(LibCloudStorage, '__init__', return_value=None):
            self.storage = LibCloudStorage()
            self.storage.driver = MockDriver()
            self.storage.bucket = 'test-bucket'

    def test_url_s3_provider(self):
        """Test URL generation for S3 provider"""
        self.storage.provider = {'type': 'libcloud.storage.types.Provider.S3_US_STANDARD_HOST'}

        # Normal file
        self.assertEqual(
            self.storage.url('test.txt'),
            'https://example.com/test-bucket/test.txt'
        )

        # Empty string (bucket URL)
        self.assertEqual(
            self.storage.url(''),
            'https://example.com/test-bucket'
        )

    def test_url_google_provider(self):
        """Test URL generation for Google provider"""
        self.storage.provider = {'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE', 'user': 'test-user'}

        # Normal file
        self.assertEqual(
            self.storage.url('test.txt'),
            'https://storage.googleapis.com/test-bucket/test.txt'
        )

        # Empty string (bucket URL)
        self.assertEqual(
            self.storage.url(''),
            'https://storage.googleapis.com/test-bucket'
        )

    def test_url_azure_provider(self):
        """Test URL generation for Azure provider"""
        self.storage.provider = {'type': 'libcloud.storage.types.Provider.AZURE_BLOBS', 'user': 'test-account'}

        # Normal file
        self.assertEqual(
            self.storage.url('test.txt'),
            'https://test-account.blob.core.windows.net/test-bucket/test.txt'
        )

        # Empty string (bucket URL)
        self.assertEqual(
            self.storage.url(''),
            'https://test-account.blob.core.windows.net/test-bucket'
        )

if __name__ == '__main__':
    unittest.main()
