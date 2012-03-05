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
    
    def tearDown(self):
        # delete all files created during each test
        name = self.storage._normalize_name(self.storage._clean_name(self.path_prefix))
        dirlist = self.storage.bucket.list(self.storage._encode_name(name))
        names = [x.name for x in dirlist]
        for name in names:
            self.storage.delete(name)
        
    def prefix_path(self, path):
        return "%s%s" % (self.path_prefix, path)
    
    def test_storage_save(self):
        name = self.prefix_path('test_storage_save.txt')
        content = 'new content'
        self.storage.save(name, ContentFile(content))
        self.assertEqual(self.storage.open(name).read(), content)
    
    def test_storage_open(self):
        name = self.prefix_path('test_open_for_writing.txt')
        content = 'new content'
        file = self.storage.open(name, 'w')
        file.write(content)
        file.close()
        self.assertEqual(self.storage.open(name, 'r').read(), content)
    
    def test_storage_exists_and_delete(self):
        # show file does not exist
        name = self.prefix_path('test_exists.txt')
        self.assertFalse(self.storage.exists(name))
        
        # create the file
        content = 'new content'
        file = self.storage.open(name, 'w')
        file.write(content)
        file.close()
        
        # show file exists
        self.assertTrue(self.storage.exists(name))
        
        # delete the file
        self.storage.delete(name)
        
        # show file does not exist
        self.assertFalse(self.storage.exists(name))
    
    def test_storage_listdir(self):
        content = 'not blank'
        file_names = ["1.txt", "2.txt", "3.txt", "4.txt"]
        for name in file_names:
            file = self.storage.open(self.prefix_path(name), 'w')
            file.write(content)
            file.close()
        file = self.storage.open(self.prefix_path('foo/bar.txt'), 'w')
        file.write(content)
        file.close()
        dirs, files = self.storage.listdir(self.path_prefix)
        for name in file_names:
            self.assertTrue(name in files)
        self.assertTrue('foo' in dirs)
        
        
        