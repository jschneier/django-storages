from datetime import datetime

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.test import TestCase
from django.utils.six import BytesIO
from dropbox.exceptions import ApiError
from dropbox.files import FileMetadata, FolderMetadata, ListFolderResult

from storages.backends import dropbox

try:
    from unittest import mock
except ImportError:  # Python 3.2 and below
    import mock


class F(object):
    pass


FILE_DATE = datetime(2015, 8, 24, 15, 6, 41)
FILE_METADATA = FileMetadata(name='foo.txt',
                             path_display='/foo.txt',
                             path_lower='/foo.txt',
                             size=4,
                             rev='23b7cdd80',
                             client_modified=FILE_DATE,
                             server_modified=FILE_DATE)

LIST_FOLDER_RESULT = ListFolderResult(entries=[
    FolderMetadata(name='bar'),
    FILE_METADATA,
], has_more=False)

FILE_MEDIA_FIXTURE = F()
FILE_MEDIA_FIXTURE.link = 'https://dl.dropboxusercontent.com/1/view/foo'


class DropBoxTest(TestCase):
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')

    def test_no_access_token(self, *args):
        with self.assertRaises(ImproperlyConfigured):
            dropbox.DropBoxStorage(None)

    @mock.patch('dropbox.Dropbox.files_delete',
                return_value=FILE_METADATA)
    def test_delete(self, *args):
        self.storage.delete('foo')

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA)
    def test_exists(self, *args):
        exists = self.storage.exists('foo')
        self.assertTrue(exists)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                side_effect=ApiError(None, None, None, None))
    def test_not_exists(self, *args):
        exists = self.storage.exists('bar')
        self.assertFalse(exists)

    @mock.patch('dropbox.Dropbox.files_list_folder',
                return_value=LIST_FOLDER_RESULT)
    def test_listdir(self, *args):
        dirs, files = self.storage.listdir('/')
        self.assertGreater(len(dirs), 0)
        self.assertGreater(len(files), 0)
        self.assertEqual(dirs[0], 'bar')
        self.assertEqual(files[0], 'foo.txt')

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA)
    def test_size(self, *args):
        size = self.storage.size('foo')
        self.assertEqual(size, FILE_METADATA.size)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA)
    def test_modified_time(self, *args):
        mtime = self.storage.modified_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    @mock.patch('dropbox.Dropbox.files_get_metadata',
                return_value=FILE_METADATA)
    def test_accessed_time(self, *args):
        mtime = self.storage.accessed_time('foo')
        self.assertEqual(mtime, FILE_DATE)

    def test_open(self, *args):
        obj = self.storage._open('foo')
        self.assertIsInstance(obj, File)

    @mock.patch('dropbox.Dropbox.files_upload',
                return_value=FILE_METADATA)
    def test_save(self, files_upload, *args):
        self.storage._save('foo', File(BytesIO(b'bar'), 'foo'))
        self.assertTrue(files_upload.called)

    @mock.patch('dropbox.Dropbox.files_upload')
    @mock.patch('dropbox.Dropbox.files_upload_session_finish')
    @mock.patch('dropbox.Dropbox.files_upload_session_append_v2')
    @mock.patch('dropbox.Dropbox.files_upload_session_start',
                return_value=mock.MagicMock(session_id='foo'))
    def test_chunked_upload(self, start, append, finish, upload):
        large_file = File(BytesIO(b'bar' * self.storage.CHUNK_SIZE), 'foo')
        self.storage._save('foo', large_file)
        self.assertTrue(start.called)
        self.assertTrue(append.called)
        self.assertTrue(finish.called)
        self.assertFalse(upload.called)

    @mock.patch('dropbox.Dropbox.files_get_temporary_link',
                return_value=FILE_MEDIA_FIXTURE)
    def test_url(self, *args):
        url = self.storage.url('foo')
        self.assertEqual(url, FILE_MEDIA_FIXTURE.link)

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/'))
        self.assertEqual(files, self.storage._full_path('.'))
        # self.assertEqual(files, self.storage._full_path('..'))
        # self.assertEqual(files, self.storage._full_path('../..'))


class DropBoxFileTest(TestCase):
    def setUp(self, *args):
        self.storage = dropbox.DropBoxStorage('foo')
        self.file = dropbox.DropBoxFile('/foo.txt', self.storage)

    # FIXME: how do I mock this?
    # @mock.patch('dropbox.Dropbox.files_download_to_file',
    #             return_value=(FILE_METADATA, Response()))
    # def test_read(self, *args):
    #     file = self.storage._open('foo')
    #     self.assertEqual(file.read(), b'bar')


@mock.patch('dropbox.Dropbox.files_list_folder',
            return_value=ListFolderResult(entries=[], has_more=False))
class DropBoxRootPathTest(TestCase):
    def test_jailed(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', '/bar')
        dirs, files = self.storage.listdir('/')
        self.assertFalse(dirs)
        self.assertFalse(files)

    # def test_suspicious(self, *args):
    #     self.storage = dropbox.DropBoxStorage('foo', '/bar')
    #     with self.assertRaises((SuspiciousFileOperation, ValueError)):
    #         self.storage._full_path('..')

    def test_formats(self, *args):
        self.storage = dropbox.DropBoxStorage('foo', '/bar')
        files = self.storage._full_path('')
        self.assertEqual(files, self.storage._full_path('/bar'))
