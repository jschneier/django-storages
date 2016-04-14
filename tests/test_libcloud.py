import os
import shutil
from django.test import TestCase
from django.core.files.base import ContentFile
from django.conf import settings

from storages.backends.apache_libcloud import LibCloudStorage
from libcloud.storage.types import ContainerAlreadyExistsError

TEST_PATH_PREFIX = 'django-storages-test'


def get_current_site_domain(*args, **kwargs):
    return "http://example.com"


class LibCloudLocalTest(TestCase):

    def _remove_libcloud_dir(self):
        if os.path.exists(settings.LIBCLOUD_DIR):
            shutil.rmtree(settings.LIBCLOUD_DIR, ignore_errors=True)

    def setUp(self):
        # Make sure the LIBCLOUD_DIR exists and is empty
        self._remove_libcloud_dir()
        os.makedirs(settings.LIBCLOUD_DIR)

        self.storage = LibCloudStorage()

        # Monkey-patch storage's get_current_site_domain since Sites table doesn't exist
        self.storage._get_current_site_domain = get_current_site_domain
        self.provider = settings.LIBCLOUD_PROVIDERS[settings.DEFAULT_LIBCLOUD_PROVIDER]
        self.provider_path = os.path.join(settings.LIBCLOUD_DIR, self.provider['bucket'])
        os.mkdir(self.provider_path)

    def tearDown(self):
        self._remove_libcloud_dir()

    def test_create_container(self):
        store = LibCloudStorage('libcloud_local')
        store.driver.create_container('test-bucket')
        new_dir = os.path.join(settings.LIBCLOUD_DIR, 'test-bucket')
        self.assertTrue(os.path.exists(new_dir))

        with self.assertRaises(ContainerAlreadyExistsError):
            store.driver.create_container('test-bucket')

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = 'test_storage_save.txt'
        content = b'new content'
        content_file = ContentFile(content)
        self.storage.save(name, content_file)
        fpath = os.path.join(self.provider_path, name)
        self.assertTrue(os.path.exists(fpath))
        with open(fpath, 'rb') as f:
            self.assertEqual(content, f.read())

    def test_url(self):
        """
        Test loading a file's url
        """
        name = 'test_url.txt'
        content = b'url test content'
        content_file = ContentFile(content)
        self.storage.save(name, content_file)

        # http://example.com/media/libcloud/local/test_url.txt
        result = get_current_site_domain() + os.path.join(settings.MEDIA_URL, 'libcloud', self.provider['bucket'], name)
        self.assertEquals(result, self.storage.url(name))
