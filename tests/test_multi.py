import os
import shutil
import tempfile

from django.core.files import storage as django_storage
from django.core.files.base import ContentFile
from django.test import TestCase

from storages.backends import multi


class MultiStorageTestCase(TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        old_path = os.path.join(self.temp_dir, "old")
        new_path = os.path.join(self.temp_dir, "new")
        os.mkdir(old_path)
        os.mkdir(new_path)
        self.storage = multi.MultiStorageHandler(
            old_storage={
                'class': 'django.core.files.storage.FileSystemStorage',
                'config': {'location': old_path},
            },
            new_storage={
                'class': 'django.core.files.storage.FileSystemStorage',
                'config': {'location': new_path},
            }
        )
        self.old_storage = django_storage.FileSystemStorage(location=old_path)
        self.new_storage = django_storage.FileSystemStorage(location=new_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)


class MultiStorageTests(MultiStorageTestCase):

    def test_old_storage_exists(self):
        self.old_storage.save('some_file', ContentFile(b'whatever'))

        self.assertFalse(self.new_storage.exists('some_file'))
        self.assertTrue(self.storage.exists('some_file'))

    def test_new_storage_exists(self):
        self.new_storage.save('some_file', ContentFile(b'whatever'))
        self.assertFalse(self.old_storage.exists('some_file'))
        self.assertTrue(self.storage.exists('some_file'))

    def test_transfer_file(self):
        self.old_storage.save('some_file', ContentFile(b'whatever'))

        self.assertFalse(self.new_storage.exists('some_file'))

        # storage.exists cause the file to be transferd to new_storage
        self.assertTrue(self.storage.exists('some_file'))
        self.assertTrue(self.new_storage.exists('some_file'))
