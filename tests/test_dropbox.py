import re
from datetime import datetime
try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock

from django.test import TestCase
from django.core.files.base import File, ContentFile
from django.core.exceptions import ImproperlyConfigured, \
                                   SuspiciousFileOperation

from storages.backends import dropbox

FILE_DATE = datetime(2015, 8, 24, 15, 6, 41)
FILE_FIXTURE = {
    'bytes': 4,
    'client_mtime': 'Mon, 24 Aug 2015 15:06:41 +0000',
    'icon': 'page_white_text',
    'is_dir': False,
    'mime_type': 'text/plain',
    'modified': 'Mon, 24 Aug 2015 15:06:41 +0000',
    'path': '/foo.txt',
    'rev': '23b7cdd80',
    'revision': 2,
    'root': 'app_folder',
    'size': '4 bytes',
    'thumb_exists': False
}
FILES_FIXTURE = {
    'bytes': 0,
    'contents': [
        FILE_FIXTURE,
        {'bytes': 0,
         'icon': 'folder',
         'is_dir': True,
         'modified': 'Mon, 6 Feb 2015 15:06:40 +0000',
         'path': '/bar',
         'rev': '33b7cdd80',
         'revision': 3,
         'root': 'app_folder',
         'size': '0 bytes',
         'thumb_exists': False}
    ],
    'hash': 'aeaa0ed65aa4f88b96dfe3d553280efc',
    'icon': 'folder',
    'is_dir': True,
    'path': '/',
    'root': 'app_folder',
    'size': '0 bytes',
    'thumb_exists': False
}
FILE_MEDIA_FIXTURE = {
    'url': 'https://dl.dropboxusercontent.com/1/view/foo',
    'expires': 'Fri, 16 Sep 2011 01:01:25 +0000',
}

__all__ = [
    'DropBoxTest',
    'DropBoxFileTest'
]


class DropBoxTest(TestCase):
    @mock.patch('dropbox.client._OAUTH2_ACCESS_TOKEN_PATTERN',
                re.compile(r'.*'))
    @mock.patch('dropbox.client.DropboxOAuth2Session')
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')

    def test_no_access_token(self, *args):
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(None)

    @mock.patch('dropbox.client.DropboxClient.file_delete',
                return_value=FILE_FIXTURE)
    def test_delete(self, *args):
        self.storage.delete('foo')

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=[FILE_FIXTURE])
    def test_exists(self, *args):
        exists = self.storage.exists('foo')
        self.assertTrue(exists)

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=[])
    def test_not_exists(self, *args):
        exists = self.storage.exists('bar')
        self.assertFalse(exists)

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=FILES_FIXTURE)
    def test_listdir(self, *args):
        dirs, files = self.storage.listdir('/')
        self.assertGreater(len(dirs), 0)
        self.assertGreater(len(files), 0)
        self.assertEqual(dirs[0], 'bar')
        self.assertEqual(files[0], 'foo.txt')

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=FILE_FIXTURE)
    def test_size(self, *args):
        size = self.storage.size('foo')
        self.assertEqual(size, FILE_FIXTURE['bytes'])

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=FILE_FIXTURE)
    def test_modified_time(self, *args):
        mtime = self.storage.modified_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    @mock.patch('dropbox.client.DropboxClient.metadata',
                return_value=FILE_FIXTURE)
    def test_accessed_time(self, *args):
        mtime = self.storage.accessed_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    def test_open(self, *args):
        obj = self.storage._open('foo')
        self.assertIsInstance(obj, File)

    @mock.patch('dropbox.client.DropboxClient.put_file',
                return_value='foo')
    def test_save(self, *args):
        self.storage._save('foo', b'bar')

    @mock.patch('dropbox.client.DropboxClient.media',
                return_value=FILE_MEDIA_FIXTURE)
    def test_url(self, *args):
        url = self.storage.url('foo')
        self.assertEqual(url, FILE_MEDIA_FIXTURE['url'])

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/'))
        self.assertEqual(files, self.storage._full_path('.'))
        self.assertEqual(files, self.storage._full_path('..'))
        self.assertEqual(files, self.storage._full_path('../..'))


class DropBoxFileTest(TestCase):
    @mock.patch('dropbox.client._OAUTH2_ACCESS_TOKEN_PATTERN',
                re.compile(r'.*'))
    @mock.patch('dropbox.client.DropboxOAuth2Session')
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        self.file = dropbox.DropBoxFile('/foo.txt', self.storage)

    @mock.patch('dropbox.client.DropboxClient.get_file',
                return_value=ContentFile(b'bar'))
    def test_read(self, *args):
        file = self.storage._open(b'foo')
        self.assertEqual(file.read(), b'bar')


@mock.patch('dropbox.client._OAUTH2_ACCESS_TOKEN_PATTERN',
            re.compile(r'.*'))
@mock.patch('dropbox.client.DropboxOAuth2Session')
@mock.patch('dropbox.client.DropboxClient.metadata',
            return_value={'contents': []})
class DropBoxRootPathTest(TestCase):
    def test_jailed(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', '/bar')
        dirs, files = self.storage.listdir('/')
        self.assertFalse(dirs)
        self.assertFalse(files)

    def test_suspicious(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', '/bar')
        with self.assertRaises((SuspiciousFileOperation, ValueError)):
            self.storage._full_path('..')

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', '/bar')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/'))
        self.assertEqual(files, self.storage._full_path('.'))
