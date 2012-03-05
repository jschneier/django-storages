from django.test import TestCase
from django.core.files.base import ContentFile
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from uuid import uuid4
import os
from storages.backends.s3boto import S3BotoStorage


class S3BotoStorageTests(TestCase):
    def setUp(self):
        self.storage = S3BotoStorage()
        
        # use a unique folder namespace for tests
        path_prefix = "test-subfolder/"
        dirs, files = self.storage.listdir(path_prefix)
        while dirs or files:
            path_prefix = "test-subfolder-%s/" % uuid4()
            dirs, files = self.storage.listdir(path_prefix)
        self.path_prefix = path_prefix
        
    def prefix_path(self, path):
        return "%s%s" % (self.path_prefix, path)
    
    def test_storage_save(self):
        name = self.prefix_path('test_storage_save.txt')
        content = 'new content'
        self.storage.save(name, ContentFile(content))
        self.assertEqual(self.storage.open(name).read(), content)
    
    def test_storage_open_for_writing(self):
        name = self.prefix_path('test_open_for_writing.txt')
        content = 'new content'
        file = self.storage.open(name, 'w')
        file.write(content)
        file.close()
        self.assertEqual(self.storage.open(name).read(), content)
        