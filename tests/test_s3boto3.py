# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import gzip
import threading
from datetime import datetime
from unittest import skipIf

from botocore.exceptions import ClientError
from django.conf import settings
from django.core.files.base import ContentFile
from django.test import TestCase
from django.utils.six.moves.urllib import parse as urlparse
from django.utils.timezone import is_aware, utc

from storages.backends import s3boto3

try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock


class S3Boto3TestCase(TestCase):
    def setUp(self):
        self.storage = s3boto3.S3Boto3Storage()
        self.storage._connections.connection = mock.MagicMock()


class S3Boto3StorageTests(S3Boto3TestCase):

    def test_clean_name(self):
        """
        Test the base case of _clean_name
        """
        path = self.storage._clean_name("path/to/somewhere")
        self.assertEqual(path, "path/to/somewhere")

    def test_clean_name_normalize(self):
        """
        Test the normalization of _clean_name
        """
        path = self.storage._clean_name("path/to/../somewhere")
        self.assertEqual(path, "path/somewhere")

    def test_clean_name_trailing_slash(self):
        """
        Test the _clean_name when the path has a trailing slash
        """
        path = self.storage._clean_name("path/to/somewhere/")
        self.assertEqual(path, "path/to/somewhere/")

    def test_clean_name_windows(self):
        """
        Test the _clean_name when the path has a trailing slash
        """
        path = self.storage._clean_name("path\\to\\somewhere")
        self.assertEqual(path, "path/to/somewhere")

    def test_storage_url_slashes(self):
        """
        Test URL generation.
        """
        self.storage.custom_domain = 'example.com'

        # We expect no leading slashes in the path,
        # and trailing slashes should be preserved.
        self.assertEqual(self.storage.url(''), 'https://example.com/')
        self.assertEqual(self.storage.url('path'), 'https://example.com/path')
        self.assertEqual(self.storage.url('path/'), 'https://example.com/path/')
        self.assertEqual(self.storage.url('path/1'), 'https://example.com/path/1')
        self.assertEqual(self.storage.url('path/1/'), 'https://example.com/path/1/')

    def test_storage_save(self):
        """
        Test saving a file
        """
        name = 'test_storage_save.txt'
        content = ContentFile('new content')
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            content.file,
            ExtraArgs={
                'ContentType': 'text/plain',
                'ACL': self.storage.default_acl,
            }
        )

    def test_content_type(self):
        """
        Test saving a file with a None content type.
        """
        name = 'test_image.jpg'
        content = ContentFile('data')
        content.content_type = None
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            content.file,
            ExtraArgs={
                'ContentType': 'image/jpeg',
                'ACL': self.storage.default_acl,
            }
        )

    def test_storage_save_gzipped(self):
        """
        Test saving a gzipped file
        """
        name = 'test_storage_save.gz'
        content = ContentFile("I am gzip'd")
        self.storage.save(name, content)
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            content.file,
            ExtraArgs={
                'ContentType': 'application/octet-stream',
                'ContentEncoding': 'gzip',
                'ACL': self.storage.default_acl,
            }
        )

    def test_storage_save_gzip(self):
        """
        Test saving a file with gzip enabled.
        """
        self.storage.gzip = True
        name = 'test_storage_save.css'
        content = ContentFile("I should be gzip'd")
        self.storage.save(name, content)
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                'ContentType': 'text/css',
                'ContentEncoding': 'gzip',
                'ACL': self.storage.default_acl,
            }
        )
        args, kwargs = obj.upload_fileobj.call_args
        content = args[0]
        zfile = gzip.GzipFile(mode='rb', fileobj=content)
        self.assertEqual(zfile.read(), b"I should be gzip'd")

    def test_storage_save_gzip_twice(self):
        """
        Test saving the same file content twice with gzip enabled.
        """
        # Given
        self.storage.gzip = True
        name = 'test_storage_save.css'
        content = ContentFile("I should be gzip'd")

        # When
        self.storage.save(name, content)
        self.storage.save('test_storage_save_2.css', content)

        # Then
        obj = self.storage.bucket.Object.return_value
        obj.upload_fileobj.assert_called_with(
            mock.ANY,
            ExtraArgs={
                'ContentType': 'text/css',
                'ContentEncoding': 'gzip',
                'ACL': self.storage.default_acl,
            }
        )
        args, kwargs = obj.upload_fileobj.call_args
        content = args[0]
        zfile = gzip.GzipFile(mode='rb', fileobj=content)
        self.assertEqual(zfile.read(), b"I should be gzip'd")

    def test_compress_content_len(self):
        """
        Test that file returned by _compress_content() is readable.
        """
        self.storage.gzip = True
        content = ContentFile("I should be gzip'd")
        content = self.storage._compress_content(content)
        self.assertTrue(len(content.read()) > 0)

    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = 'test_open_for_writïng.txt'
        content = 'new content'

        # Set the encryption flag used for multipart uploads
        self.storage.encryption = True
        self.storage.reduced_redundancy = True
        self.storage.default_acl = 'public-read'

        file = self.storage.open(name, 'w')
        self.storage.bucket.Object.assert_called_with(name)
        obj = self.storage.bucket.Object.return_value
        # Set the name of the mock object
        obj.key = name

        file.write(content)
        obj.initiate_multipart_upload.assert_called_with(
            ACL='public-read',
            ContentType='text/plain',
            ServerSideEncryption='AES256',
            StorageClass='REDUCED_REDUNDANCY'
        )

        # Save the internal file before closing
        multipart = obj.initiate_multipart_upload.return_value
        multipart.parts.all.return_value = [mock.MagicMock(e_tag='123', part_number=1)]
        file.close()
        multipart.Part.assert_called_with(1)
        part = multipart.Part.return_value
        part.upload.assert_called_with(Body=content.encode('utf-8'))
        multipart.complete.assert_called_once_with(
            MultipartUpload={'Parts': [{'ETag': '123', 'PartNumber': 1}]})

    def test_auto_creating_bucket(self):
        self.storage.auto_create_bucket = True
        Bucket = mock.MagicMock()
        self.storage._connections.connection.Bucket.return_value = Bucket
        self.storage._connections.connection.meta.client.meta.region_name = 'sa-east-1'

        Bucket.meta.client.head_bucket.side_effect = ClientError({'Error': {},
                                                                  'ResponseMetadata': {'HTTPStatusCode': 404}},
                                                                 'head_bucket')
        self.storage._get_or_create_bucket('testbucketname')
        Bucket.create.assert_called_once_with(
            ACL='public-read',
            CreateBucketConfiguration={
                'LocationConstraint': 'sa-east-1',
            }
        )

    def test_storage_exists(self):
        self.assertTrue(self.storage.exists("file.txt"))
        self.storage.connection.meta.client.head_object.assert_called_with(
            Bucket=self.storage.bucket_name,
            Key="file.txt",
        )

    def test_storage_exists_false(self):
        self.storage.connection.meta.client.head_object.side_effect = ClientError(
            {'Error': {'Code': '404', 'Message': 'Not Found'}},
            'HeadObject',
        )
        self.assertFalse(self.storage.exists("file.txt"))
        self.storage.connection.meta.client.head_object.assert_called_with(
            Bucket=self.storage.bucket_name,
            Key='file.txt',
        )

    def test_storage_exists_doesnt_create_bucket(self):
        with mock.patch.object(self.storage, '_get_or_create_bucket') as method:
            self.storage.exists('file.txt')
            method.assert_not_called()

    def test_storage_delete(self):
        self.storage.delete("path/to/file.txt")
        self.storage.bucket.Object.assert_called_with('path/to/file.txt')
        self.storage.bucket.Object.return_value.delete.assert_called_with()

    def test_storage_listdir_base(self):
        file_names = ["some/path/1.txt", "2.txt", "other/path/3.txt", "4.txt"]

        result = []
        for p in file_names:
            obj = mock.MagicMock()
            obj.key = p
            result.append(obj)
        self.storage.bucket.objects.filter.return_value = iter(result)

        dirs, files = self.storage.listdir("")
        self.storage.bucket.objects.filter.assert_called_with(Prefix="")

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

        result = []
        for p in file_names:
            obj = mock.MagicMock()
            obj.key = p
            result.append(obj)
        self.storage.bucket.objects.filter.return_value = iter(result)

        dirs, files = self.storage.listdir("some/")
        self.storage.bucket.objects.filter.assert_called_with(Prefix="some/")

        self.assertEqual(len(dirs), 1)
        self.assertTrue('path' in dirs,
                        """ "path" not in directory list "%s".""" % (dirs,))

        self.assertEqual(len(files), 1)
        self.assertTrue('2.txt' in files,
                        """ "2.txt" not in files list "%s".""" % (files,))

    def test_storage_size(self):
        obj = self.storage.bucket.Object.return_value
        obj.content_length = 4098

        name = 'file.txt'
        self.assertEqual(self.storage.size(name), obj.content_length)

    def test_storage_mtime(self):
        # Test both USE_TZ cases
        for use_tz in (True, False):
            with self.settings(USE_TZ=use_tz):
                self._test_storage_mtime(use_tz)

    def _test_storage_mtime(self, use_tz):
        obj = self.storage.bucket.Object.return_value
        obj.last_modified = datetime.now(utc)

        name = 'file.txt'
        self.assertFalse(
            is_aware(self.storage.modified_time(name)),
            'Naive datetime object expected from modified_time()'
        )

        self.assertIs(
            settings.USE_TZ,
            is_aware(self.storage.get_modified_time(name)),
            '%s datetime object expected from get_modified_time() when USE_TZ=%s' % (
                ('Naive', 'Aware')[settings.USE_TZ],
                settings.USE_TZ
            )
        )

    def test_storage_url(self):
        name = 'test_storage_size.txt'
        url = 'http://aws.amazon.com/%s' % name
        self.storage.bucket.meta.client.generate_presigned_url.return_value = url
        self.storage.bucket.name = 'bucket'
        self.assertEqual(self.storage.url(name), url)
        self.storage.bucket.meta.client.generate_presigned_url.assert_called_with(
            'get_object',
            Params={'Bucket': self.storage.bucket.name, 'Key': name},
            ExpiresIn=self.storage.querystring_expire
        )

        custom_expire = 123

        self.assertEqual(self.storage.url(name, expire=custom_expire), url)
        self.storage.bucket.meta.client.generate_presigned_url.assert_called_with(
            'get_object',
            Params={'Bucket': self.storage.bucket.name, 'Key': name},
            ExpiresIn=custom_expire
        )

    def test_generated_url_is_encoded(self):
        self.storage.custom_domain = "mock.cloudfront.net"
        filename = "whacky & filename.mp4"
        url = self.storage.url(filename)
        parsed_url = urlparse.urlparse(url)
        self.assertEqual(parsed_url.path,
                         "/whacky%20%26%20filename.mp4")
        self.assertFalse(self.storage.bucket.meta.client.generate_presigned_url.called)

    def test_special_characters(self):
        self.storage.custom_domain = "mock.cloudfront.net"

        name = "ãlöhâ.jpg"
        content = ContentFile('new content')
        self.storage.save(name, content)
        self.storage.bucket.Object.assert_called_once_with(name)

        url = self.storage.url(name)
        parsed_url = urlparse.urlparse(url)
        self.assertEqual(parsed_url.path, "/%C3%A3l%C3%B6h%C3%A2.jpg")

    def test_strip_signing_parameters(self):
        expected = 'http://bucket.s3-aws-region.amazonaws.com/foo/bar'
        self.assertEqual(self.storage._strip_signing_parameters(
            '%s?X-Amz-Date=12345678&X-Amz-Signature=Signature' % expected), expected)
        self.assertEqual(self.storage._strip_signing_parameters(
            '%s?expires=12345678&signature=Signature' % expected), expected)

    @skipIf(threading is None, 'Test requires threading')
    def test_connection_threading(self):
        connections = []

        def thread_storage_connection():
            connections.append(self.storage.connection)

        for x in range(2):
            t = threading.Thread(target=thread_storage_connection)
            t.start()
            t.join()

        # Connection for each thread needs to be unique
        self.assertIsNot(connections[0], connections[1])
