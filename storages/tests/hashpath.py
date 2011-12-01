import os
import shutil

from django.test import TestCase
from django.core.files.base import ContentFile
from django.conf import settings

from storages.backends.hashpath import HashPathStorage

TEST_PATH_PREFIX = 'django-storages-test'


class HashPathStorageTest(TestCase):

    def setUp(self):
        self.test_path = os.path.join(settings.MEDIA_ROOT, TEST_PATH_PREFIX)
        self.storage = HashPathStorage(location=self.test_path)

        # make sure the profile upload folder exists
        if not os.path.exists(self.test_path):
            os.makedirs(self.test_path)

    def tearDown(self):
        # remove uploaded profile picture
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)

    def test_save_same_file(self):
        """
        saves a file twice, the file should only be stored once, because the
        content/hash is the same
        """
        
        path_1 = self.storage.save('test', ContentFile('new content'))
        
        path_2 = self.storage.save('test', ContentFile('new content'))

        self.assertEqual(path_1, path_2)
