import stat
from datetime import datetime
try:
    from unittest.mock import patch, MagicMock
except ImportError:  # Python 3.2 and below
    from mock import patch, MagicMock
from django.test import TestCase
from django.core.files.base import File
from django.utils.six import BytesIO
from storages.backends import sftpstorage


class SFTPStorageTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage('foo')

    def test_init(self):
        pass

    @patch('paramiko.SSHClient')
    def test_connect(self, mock_ssh):
        self.storage._connect()
        self.assertEqual('foo', mock_ssh.return_value.connect.call_args[0][0])

    def test_open(self):
        file_ = self.storage._open('foo')
        self.assertIsInstance(file_, sftpstorage.SFTPStorageFile)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_read(self, mock_sftp):
        file_ = self.storage._read('foo')
        self.assertTrue(mock_sftp.open.called)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_chown(self, mock_sftp):
        self.storage._chown('foo', 1, 1)
        self.assertEqual(mock_sftp.chown.call_args[0], ('foo', 1, 1))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_mkdir(self, mock_sftp):
        self.storage._mkdir('foo')
        self.assertEqual(mock_sftp.mkdir.call_args[0], ('foo',))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.side_effect': (IOError(), True)
    })
    def test_mkdir_parent(self, mock_sftp):
        self.storage._mkdir('bar/foo')
        self.assertEqual(mock_sftp.mkdir.call_args_list[0][0], ('bar',))
        self.assertEqual(mock_sftp.mkdir.call_args_list[1][0], ('bar/foo',))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_save(self, mock_sftp):
        self.storage._save('foo', File(BytesIO(b'foo'), 'foo'))
        self.assertTrue(mock_sftp.open.return_value.write.called)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.side_effect': (IOError(), True)
    })
    def test_save_in_subdir(self, mock_sftp):
        self.storage._save('bar/foo', File(BytesIO(b'foo'), 'foo'))
        self.assertEqual(mock_sftp.mkdir.call_args_list[0][0], ('bar',))
        self.assertTrue(mock_sftp.open.return_value.write.called)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_delete(self, mock_sftp):
        self.storage.delete('foo')
        self.assertEqual(mock_sftp.remove.call_args_list[0][0], ('foo',))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_exists(self, mock_sftp):
        self.assertTrue(self.storage.exists('foo'))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.side_effect': IOError()
    })
    def test_not_exists(self, mock_sftp):
        self.assertFalse(self.storage.exists('foo'))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'listdir_attr.return_value':
            [MagicMock(filename='foo', st_mode=stat.S_IFDIR),
             MagicMock(filename='bar', st_mode=None)]})
    def test_listdir(self, mock_sftp):
        dirs, files = self.storage.listdir('/')
        self.assertTrue(dirs)
        self.assertTrue(files)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.return_value.st_size': 42,
    })
    def test_size(self, mock_sftp):
        self.assertEqual(self.storage.size('foo'), 42)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.return_value.st_atime': 1469674684.000000,
    })
    def test_accessed_time(self, mock_sftp):
        self.assertEqual(self.storage.accessed_time('foo'),
                         datetime(2016, 7, 27, 21, 58, 4))

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.return_value.st_mtime': 1469674684.000000,
    })
    def test_modified_time(self, mock_sftp):
        self.assertEqual(self.storage.modified_time('foo'),
                         datetime(2016, 7, 27, 21, 58, 4))

    def test_url(self):
        self.assertEqual(self.storage.url('foo'), '/media/foo')
        # Test custom
        self.storage._base_url = 'http://bar.pt/'
        self.assertEqual(self.storage.url('foo'), 'http://bar.pt/foo')
        # Test error
        with self.assertRaises(ValueError):
            self.storage._base_url = None
            self.storage.url('foo')


class SFTPStorageFileTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage('foo')
        self.file = sftpstorage.SFTPStorageFile('bar', self.storage, 'wb')

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.return_value.st_size': 42,
    })
    def test_size(self, mock_sftp):
        self.assertEqual(self.file.size, 42)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'open.return_value.read.return_value': b'foo',
    })
    def test_read(self, mock_sftp):
        self.assertEqual(self.file.read(), b'foo')
        self.assertTrue(mock_sftp.open.called)

    def test_write(self):
        self.file.write(b'foo')
        self.assertEqual(self.file.file.read(), b'foo')

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_close(self, mock_sftp):
        self.file.write(b'foo')
        self.file.close()
        self.assertTrue(mock_sftp.open.return_value.write.called)
