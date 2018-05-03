try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock

import datetime

from boto.exception import S3ResponseError
from boto.s3.key import Key
from boto.utils import ISO8601, parse_ts
from django.core.files.base import ContentFile
from django.test import TestCase
from django.utils import timezone as tz
from django.utils.six.moves.urllib import parse as urlparse

from storages.backends import s3boto


class S3BotoTestCase(TestCase):
    @mock.patch('storages.backends.s3boto.S3Connection')
    def setUp(self, S3Connection):
        self.storage = s3boto.S3BotoStorage()
        self.storage._connection = mock.MagicMock()


class S3BotoStorageTests(S3BotoTestCase):

    def test_clean_name(self):
        """
        Test the base case of _clean_name - more tests are performed in
        test_utils
        """
        path = self.storage._clean_name("path/to/somewhere")
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
        self.storage.bucket.get_key.assert_called_once_with(name)

        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type', 'text/plain')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={'Content-Type': 'text/plain'},
            policy=self.storage.default_acl,
            reduced_redundancy=self.storage.reduced_redundancy,
            rewind=True
        )

    def test_content_type(self):
        """
        Test saving a file with a None content type.
        """
        name = 'test_image.jpg'
        content = ContentFile('data')
        content.content_type = None
        self.storage.save(name, content)
        self.storage.bucket.get_key.assert_called_once_with(name)

        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type', 'image/jpeg')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={'Content-Type': 'image/jpeg'},
            policy=self.storage.default_acl,
            reduced_redundancy=self.storage.reduced_redundancy,
            rewind=True
        )

    def test_storage_save_gzipped(self):
        """
        Test saving a gzipped file
        """
        name = 'test_storage_save.gz'
        content = ContentFile("I am gzip'd")
        self.storage.save(name, content)
        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type',
                                            'application/octet-stream')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={'Content-Type': 'application/octet-stream',
                     'Content-Encoding': 'gzip'},
            policy=self.storage.default_acl,
            reduced_redundancy=self.storage.reduced_redundancy,
            rewind=True,
        )

    def test_storage_save_gzip(self):
        """
        Test saving a file with gzip enabled.
        """
        self.storage.gzip = True
        name = 'test_storage_save.css'
        content = ContentFile("I should be gzip'd")
        self.storage.save(name, content)
        key = self.storage.bucket.get_key.return_value
        key.set_metadata.assert_called_with('Content-Type', 'text/css')
        key.set_contents_from_file.assert_called_with(
            content,
            headers={'Content-Type': 'text/css', 'Content-Encoding': 'gzip'},
            policy=self.storage.default_acl,
            reduced_redundancy=self.storage.reduced_redundancy,
            rewind=True,
        )

    def test_compress_content_len(self):
        """
        Test that file returned by _compress_content() is readable.
        """
        content = ContentFile("I should be gzip'd")
        content = self.storage._compress_content(content)
        self.assertTrue(len(content.read()) > 0)

    def test_storage_open_write(self):
        """
        Test opening a file in write mode
        """
        name = 'test_open_for_writing.txt'
        content = 'new content'

        # Set the encryption flag used for multipart uploads
        self.storage.encryption = True
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
            headers={
                'Content-Type': 'text/plain',
                'x-amz-acl': 'public-read',
            },
            reduced_redundancy=self.storage.reduced_redundancy,
            encrypt_key=True,
        )

        # Save the internal file before closing
        _file = file.file
        file.close()
        file._multipart.upload_part_from_file.assert_called_with(
            _file, 1, headers=self.storage.headers,
        )
        file._multipart.complete_upload.assert_called_once_with()

    def test_storage_exists_bucket(self):
        self.storage._connection.get_bucket.side_effect = S3ResponseError(404, 'No bucket')
        self.assertFalse(self.storage.exists(''))

        self.storage._connection.get_bucket.side_effect = None
        self.assertTrue(self.storage.exists(''))

    def test_storage_exists(self):
        self.storage.bucket.get_key.return_value = mock.MagicMock(spec=Key)
        self.assertTrue(self.storage.exists("file.txt"))

    def test_storage_exists_false(self):
        self.storage.bucket.get_key.return_value = None
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

        kwargs = {
            'method': 'GET',
            'bucket': self.storage.bucket.name,
            'key': name,
            'query_auth': self.storage.querystring_auth,
            'force_http': not self.storage.secure_urls,
            'headers': None,
            'response_headers': None,
        }

        self.assertEqual(self.storage.url(name), url)
        self.storage.connection.generate_url.assert_called_with(
            self.storage.querystring_expire,
            **kwargs
        )

        custom_expire = 123

        self.assertEqual(self.storage.url(name, expire=custom_expire), url)
        self.storage.connection.generate_url.assert_called_with(
            custom_expire,
            **kwargs
        )

    def test_generated_url_is_encoded(self):
        self.storage.custom_domain = "mock.cloudfront.net"
        filename = "whacky & filename.mp4"
        url = self.storage.url(filename)
        parsed_url = urlparse.urlparse(url)
        self.assertEqual(parsed_url.path,
                         "/whacky%20%26%20filename.mp4")

    def test_new_file_modified_time(self):
        self.storage.preload_metadata = True
        name = 'test_storage_save.txt'
        content = ContentFile('new content')
        utcnow = datetime.datetime.utcnow()
        with mock.patch('storages.backends.s3boto.datetime') as mock_datetime, self.settings(TIME_ZONE='UTC'):
            mock_datetime.utcnow.return_value = utcnow
            self.storage.save(name, content)
            self.assertEqual(self.storage.modified_time(name),
                             parse_ts(utcnow.strftime(ISO8601)))

    @mock.patch('storages.backends.s3boto.S3BotoStorage._get_key')
    def test_get_modified_time(self, getkey):
        utcnow = datetime.datetime.utcnow().strftime(ISO8601)

        with self.settings(USE_TZ=True, TIME_ZONE='America/New_York'):
            key = mock.MagicMock(spec=Key)
            key.last_modified = utcnow
            getkey.return_value = key
            modtime = self.storage.get_modified_time('foo')
            self.assertFalse(tz.is_naive(modtime))
            self.assertEqual(modtime,
                             tz.make_aware(datetime.datetime.strptime(utcnow, ISO8601), tz.utc))

        with self.settings(USE_TZ=False, TIME_ZONE='America/New_York'):
            key = mock.MagicMock(spec=Key)
            key.last_modified = utcnow
            getkey.return_value = key
            modtime = self.storage.get_modified_time('foo')
            self.assertTrue(tz.is_naive(modtime))
            self.assertEqual(modtime,
                             tz.make_naive(tz.make_aware(
                                datetime.datetime.strptime(utcnow, ISO8601), tz.utc)))
