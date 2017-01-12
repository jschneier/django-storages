import os
import shutil

from django.test import TestCase
from django.core.files.base import ContentFile
from django.conf import settings

from storages.backends.azure_storage import AzureStorage

TEST_PATH_PREFIX = 'django-storages-test'


class Azure_StorageTest(TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_save_same_file(self):
        """
        This is a basic test case that will be commented out until a good way to support it will be found
        """
        #storage = AzureStorage()
        #storage._save('testfile','1234')
        pass