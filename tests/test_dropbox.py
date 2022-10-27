import io
from datetime import datetime
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import SuspiciousFileOperation
from django.core.files.base import File
from django.test import TestCase
from dropbox.files import FileMetadata
from dropbox.files import FolderMetadata
from dropbox.files import GetTemporaryLinkResult
from requests.models import Response

from storages.backends import dropbox

FILE_DATE = datetime(2015, 8, 24, 15, 6, 41)
FILE_METADATA_MOCK = mock.MagicMock(spec=FileMetadata)
FILE_METADATA_MOCK.size = 4
FILE_METADATA_MOCK.client_modified = FILE_DATE
FILE_METADATA_MOCK.server_modified = FILE_DATE
FILE_METADATA_MOCK.path_lower = '/foo.txt'
FILE_METADATA_MOCK.path_display = '/foo.txt'
FILE_METADATA_MOCK.name = 'foo.txt'
FILE_METADATA_MOCK.rev = '012c0000000150c838f0'
FILE_METADATA_MOCK.content_hash = \
    '3865695d47c02576e8578df30d56bb3faf737c11044d804f09ffb6484453020f'

FOLDER_METADATA_MOCK = mock.MagicMock(spec=FolderMetadata)
FOLDER_METADATA_MOCK.name = 'bar'

FILES_MOCK = mock.MagicMock(spec=FolderMetadata)
FILES_MOCK.entries = [
    FILE_METADATA_MOCK, FOLDER_METADATA_MOCK
]

FILE_MEDIA_MOCK = mock.MagicMock(spec=GetTemporaryLinkResult)
FILE_MEDIA_MOCK.link = 'https://dl.dropboxusercontent.com/1/view/foo'

FILES_EMPTY_MOCK = mock.MagicMock(spec=FolderMetadata)
FILES_EMPTY_MOCK.entries = []

RESPONSE_200_MOCK = mock.MagicMock(spec=Response)
RESPONSE_200_MOCK.status_code = 200
RESPONSE_200_MOCK.content = b'bar'

RESPONSE_500_MOCK = mock.MagicMock(spec=Response)
RESPONSE_500_MOCK.status_code = 500


class DropBoxTest(TestCase):
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')

    def test_no_access_token(self, *args):
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(None)

    def test_refresh_token_app_key_no_app_secret(self, *args):
        inputs = {
            'oauth2_refresh_token': 'foo',
            'app_key': 'bar',
        }
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(**inputs)

    def test_refresh_token_app_secret_no_app_key(self, *args):
        inputs = {
            'oauth2_refresh_token': 'foo',
            'app_secret': 'bar',
        }
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(**inputs)

    def test_app_key_app_secret_no_refresh_token(self, *args):
        inputs = {
            'app_key': 'foo',
            'app_secret': 'bar',
        }
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(**inputs)

    @mock.patch('dropbox.Dropbox.files_delete',
                return_value=FILE_METADATA_MOCK)
    def test_delete(self, *args):
        self.storage.delete('foo')

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=[FILE_METADATA_MOCK])
    def test_exists(self, *args):
        exists = self.storage.exists('foo')
        self.assertTrue(exists)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=[])
    def test_not_exists(self, *args):
        exists = self.storage.exists('bar')
        self.assertFalse(exists)

    @mock.patch('dropbox.Dropbox.files_list_folder',
                return_value=FILES_MOCK)
    def test_listdir(self, *args):
        dirs, files = self.storage.listdir('/')
        dirs2, files2 = self.storage.listdir('')
        self.assertEqual(dirs, dirs2)
        self.assertEqual(files2, files2)

        self.assertGreater(len(dirs), 0)
        self.assertGreater(len(files), 0)
        self.assertEqual(dirs[0], 'bar')
        self.assertEqual(files[0], 'foo.txt')

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA_MOCK)
    def test_size(self, *args):
        size = self.storage.size('foo')
        self.assertEqual(size, FILE_METADATA_MOCK.size)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA_MOCK)
    def test_modified_time(self, *args):
        mtime = self.storage.modified_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA_MOCK)
    def test_accessed_time(self, *args):
        mtime = self.storage.accessed_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    def test_open(self, *args):
        obj = self.storage._open('foo')
        self.assertIsInstance(obj, File)

    @mock.patch('dropbox.Dropbox.files_upload', return_value='foo')
    @mock.patch('dropbox.Dropbox.files_get_metadata', return_value=None)
    def test_save(self, files_upload, *args):
        name = self.storage.save('foo', File(io.BytesIO(b'bar'), 'foo'))
        self.assertTrue(files_upload.called)
        self.assertEqual(name, 'foo')

    @mock.patch('dropbox.Dropbox.files_upload')
    @mock.patch('dropbox.Dropbox.files_upload_session_finish')
    @mock.patch('dropbox.Dropbox.files_upload_session_append_v2')
    @mock.patch('dropbox.Dropbox.files_upload_session_start',
                return_value=mock.MagicMock(session_id='foo'))
    def test_chunked_upload(self, start, append, finish, upload):
        large_file = File(io.BytesIO(b'bar' * self.storage.CHUNK_SIZE), 'foo')
        self.storage._save('foo', large_file)
        self.assertTrue(start.called)
        self.assertTrue(append.called)
        self.assertTrue(finish.called)
        self.assertFalse(upload.called)

    @mock.patch('dropbox.Dropbox.files_get_temporary_link',
                return_value=FILE_MEDIA_MOCK)
    def test_url(self, *args):
        url = self.storage.url('foo')
        self.assertEqual(url, FILE_MEDIA_MOCK.link)

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/'))
        self.assertEqual(files, self.storage._full_path('.'))
        self.assertEqual(files, self.storage._full_path('..'))
        self.assertEqual(files, self.storage._full_path('../..'))


class DropBoxFileTest(TestCase):
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        self.file = dropbox.DropBoxFile('/foo.txt', self.storage)

    @mock.patch('dropbox.Dropbox.files_download',
                return_value=(FILE_METADATA_MOCK, RESPONSE_200_MOCK))
    def test_read(self, *args):
        file = self.storage._open('foo.txt')
        self.assertEqual(file.read(), b'bar')

    @mock.patch('dropbox.Dropbox.files_download',
                return_value=(FILE_METADATA_MOCK, RESPONSE_500_MOCK))
    def test_server_bad_response(self, *args):
        with self.assertRaises(dropbox.DropBoxStorageException):
            file = self.storage._open('foo.txt')
            file.read()


@mock.patch('dropbox.Dropbox.files_list_folder',
            return_value=FILES_EMPTY_MOCK)
class DropBoxRootPathTest(TestCase):
    def test_jailed(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', root_path='/bar')
        dirs, files = self.storage.listdir('/')
        self.assertFalse(dirs)
        self.assertFalse(files)

    @mock.patch('dropbox.Dropbox.files_upload', return_value='foo')
    @mock.patch('dropbox.Dropbox.files_get_metadata', return_value=None)
    def test_saves(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', root_path='/bar')
        name = self.storage.save('xyz', File(io.BytesIO(b'abc'), 'def'))
        self.assertEqual(name, 'xyz')

    def test_suspicious(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', root_path='/bar')
        with self.assertRaises((SuspiciousFileOperation, ValueError)):
            self.storage._full_path('..')

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', root_path='/bar')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/'))
        self.assertEqual(files, self.storage._full_path('.'))
