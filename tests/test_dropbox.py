import re
from datetime import datetime
try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock

from django.test import TestCase
from django.core.files.base import File, ContentFile

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

__all__ = [
    'DropBoxTest',
    'DropBoxFileTest'
]


class DropBoxTest(TestCase):
    @mock.patch('dropbox.client._OAUTH2_ACCESS_TOKEN_PATTERN',
                re.compile(r'.*'))
    @mock.patch('dropbox.client.DropboxOAuth2Session')
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('')

    @mock.patch('dropbox.client.DropboxClient.file_delete',
                return_value=FILE_FIXTURE)
    def test_delete(self, *args):
        self.storage.delete('foo')

    @mock.patch('dropbox.client.DropboxClient.search',
                return_value=[FILE_FIXTURE])
    def test_exists(self, *args):
        exists = self.storage.exists('foo')
        self.assertTrue(exists)

    @mock.patch('dropbox.client.DropboxClient.search',
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
        self.assertEqual(dirs[0], '/bar')
        self.assertEqual(files[0], '/foo.txt')

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

    @mock.patch('dropbox.client.DropboxClient.get_file',
                return_value=ContentFile('bar'))
    def test_read(self, *args):
        content = self.storage._read('foo')
        self.assertEqual(content, 'bar')


class DropBoxFileTest(TestCase):
    @mock.patch('dropbox.client._OAUTH2_ACCESS_TOKEN_PATTERN',
                re.compile(r'.*'))
    @mock.patch('dropbox.client.DropboxOAuth2Session')
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('')
        self.file = dropbox.DropBoxFile('/foo.txt', self.storage)

    @mock.patch('dropbox.client.DropboxClient.put_file',
                return_value='foo')
    def test_write(self, *args):
        self.storage._save('foo', b'bar')

    @mock.patch('dropbox.client.DropboxClient.get_file',
                return_value=ContentFile('bar'))
    def test_read(self, *args):
        content = self.storage._read('foo')
        self.assertEqual(content, 'bar')
