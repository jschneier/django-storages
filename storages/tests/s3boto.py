import mock

from django.test import TestCase
from django.core.files.base import ContentFile

from boto.s3.key import Key

from storages.backends import s3boto

__all__ = (
    'SafeJoinTest',
    'S3BotoStorageTests',
    #'S3BotoStorageFileTests',
)

class S3BotoTestCase(TestCase):
    @mock.patch('storages.backends.s3boto.S3Connection')
    def setUp(self, S3Connection):
        self.storage = s3boto.S3BotoStorage()


class SafeJoinTest(TestCase):
    def test_normal(self):
        path = s3boto.safe_join("", "path/to/somewhere", "other", "path/to/somewhere")
        self.assertEquals(path, "path/to/somewhere/other/path/to/somewhere")

    def test_with_dot(self):
        path = s3boto.safe_join("", "path/./somewhere/../other", "..",
                                ".", "to/./somewhere")
        self.assertEquals(path, "path/to/somewhere")

    def test_base_url(self):
        path = s3boto.safe_join("base_url", "path/to/somewhere")
        self.assertEquals(path, "base_url/path/to/somewhere")

    def test_base_url_with_slash(self):
        path = s3boto.safe_join("base_url/", "path/to/somewhere")
        self.assertEquals(path, "base_url/path/to/somewhere")

    def test_suspicious_operation(self):
        self.assertRaises(ValueError,
            s3boto.safe_join, "base", "../../../../../../../etc/passwd")
    
class S3BotoStorageTests(S3BotoTestCase):

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = 'test_storage_save.txt'
        content = ContentFile('new content')
        self.storage.save(name, content)
        self.storage.bucket.get_key.assert_called_once_with(name)
        
        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type', 'text/plain')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={},
            policy=self.storage.acl,
            reduced_redundancy=self.storage.reduced_redundancy,
        )
    
    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = 'test_open_for_writing.txt'
        content = 'new content'

        # Set the ACL header used when creating/writing data.
        self.storage.bucket.connection.provider.acl_header = 'x-amz-acl'
        # Set the mocked key's bucket
        self.storage.bucket.get_key.return_value.bucket = self.storage.bucket
        # Set the name of the mock object
        self.storage.bucket.get_key.return_value.name = name 

        file = self.storage.open(name, 'w')
        self.storage.bucket.get_key.assert_called_with(name)

        file.write(content)
        self.storage.bucket.initiate_multipart_upload.assert_called_with(
            name,
            headers={'x-amz-acl': 'public-read'},
            reduced_redundancy=self.storage.reduced_redundancy,
        )

        # Save the internal file before closing
        _file = file.file
        file.close()
        file._multipart.upload_part_from_file.assert_called_with(
            _file, 1, headers=self.storage.headers,
        )
        file._multipart.complete_upload.assert_called_once()
    
    def test_storage_exists(self):
        key = self.storage.bucket.new_key.return_value
        key.exists.return_value = True
        self.assertTrue(self.storage.exists("file.txt"))

    def test_storage_exists_false(self):
        key = self.storage.bucket.new_key.return_value
        key.exists.return_value = False 
        self.assertFalse(self.storage.exists("file.txt"))

    def test_storage_delete(self):
        self.storage.delete("path/to/file.txt")
        self.storage.bucket.delete_key.assert_called_with("path/to/file.txt")

    def test_storage_listdir_base(self):
        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]

        self.storage.bucket.list.return_value = []
        for p in file_names:
            key = mock.MagicMock(spec=Key)
            key.name = p
            self.storage.bucket.list.return_value.append(key)

        dirs, files = self.storage.listdir("")

        self.assertEqual(len(dirs), 2)
        for directory in ["some", "other"]:
            self.assertTrue(directory in dirs, 
                            """ "%s" not in directory list "%s".""" % (
                                directory, dirs))
            
        self.assertEqual(len(files), 2)
        for filename in ["2.txt", "4.txt"]:
            self.assertTrue(filename in files, 
                            """ "%s" not in file list "%s".""" % (
                                filename, files))

    def test_storage_listdir_subdir(self):
        file_names = ["some/path/1.txt", "some/2.txt"]

        self.storage.bucket.list.return_value = []
        for p in file_names:
            key = mock.MagicMock(spec=Key)
            key.name = p
            self.storage.bucket.list.return_value.append(key)

        dirs, files = self.storage.listdir("some/")
        self.assertEqual(len(dirs), 1)
        self.assertTrue('path' in dirs, 
                        """ "path" not in directory list "%s".""" % (dirs,))
            
        self.assertEqual(len(files), 1)
        self.assertTrue('2.txt' in files, 
                        """ "2.txt" not in files list "%s".""" % (files,))

    def test_storage_size(self):
        key = self.storage.bucket.get_key.return_value
        key.size = 4098

        name = 'file.txt'
        self.assertEqual(self.storage.size(name), key.size)

    def test_storage_url(self):
        name = 'test_storage_size.txt'
        url = 'http://aws.amazon.com/%s' % name
        self.storage.connection.generate_url.return_value = url

        self.assertEquals(self.storage.url(name), url)
        self.storage.connection.generate_url.assert_called_with(
            self.storage.querystring_expire,
            method='GET',
            bucket=self.storage.bucket.name,
            key=name,
            query_auth=self.storage.querystring_auth,
            force_http=not self.storage.secure_urls,
        )
        
#class S3BotoStorageFileTests(S3BotoTestCase):
#    def test_multipart_upload(self):
#        nparts = 2
#        name = self.prefix_path("test_multipart_upload.txt")
#        mode = 'w'
#        f = s3boto.S3BotoStorageFile(name, mode, self.storage)
#        content_length = 1024 * 1024# 1 MB
#        content = 'a' * content_length
#        
#        bytes = 0
#        target = f._write_buffer_size * nparts
#        while bytes < target:
#            f.write(content)
#            bytes += content_length
#            
#        # make the buffer roll over so f._write_counter
#        # is incremented
#        f.write("finished")
#        
#        # verify upload was multipart and correctly partitioned
#        self.assertEqual(f._write_counter, nparts)
#        
#        # complete the upload
#        f.close()
#        
#        # verify that the remaining buffered bytes were
#        # uploaded when the file was closed.
#        self.assertEqual(f._write_counter, nparts+1)
