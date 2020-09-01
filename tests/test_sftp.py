import io
import os
import stat
from datetime import datetime
from unittest.mock import MagicMock, patch

import paramiko
from django.core.files.base import File
from django.test import TestCase, override_settings

from storages.backends import sftpstorage


class SFTPStorageTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage(host='foo')

    def test_init(self):
        pass

    @patch('paramiko.SSHClient')
    def test_no_known_hosts_file(self, mock_ssh):
        self.storage._known_host_file = "not_existed_file"
        self.storage._connect()
        self.assertEqual('foo', mock_ssh.return_value.connect.call_args[0][0])

    @patch.object(os.path, "expanduser", return_value="/path/to/known_hosts")
    @patch.object(os.path, "exists", return_value=True)
    @patch('paramiko.SSHClient')
    def test_error_when_known_hosts_file_not_defined(self, mock_ssh, *a):
        self.storage._connect()
        self.storage._ssh.load_host_keys.assert_called_once_with("/path/to/known_hosts")

    @patch('paramiko.SSHClient')
    def test_connect(self, mock_ssh):
        self.storage._connect()
        self.assertEqual('foo', mock_ssh.return_value.connect.call_args[0][0])

    def test_open(self):
        file_ = self.storage._open('foo')
        self.assertIsInstance(file_, sftpstorage.SFTPStorageFile)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp')
    def test_read(self, mock_sftp):
        self.storage._read('foo')
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
        self.storage._save('foo', File(io.BytesIO(b'foo'), 'foo'))
        self.assertTrue(mock_sftp.open.return_value.write.called)

    @patch('storages.backends.sftpstorage.SFTPStorage.sftp', **{
        'stat.side_effect': (IOError(), True)
    })
    def test_save_in_subdir(self, mock_sftp):
        self.storage._save('bar/foo', File(io.BytesIO(b'foo'), 'foo'))
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

    @patch('paramiko.transport.Transport', **{
        'is_active.side_effect': (True, False)
    })
    @patch('storages.backends.sftpstorage.SFTPStorage._connect')
    def test_sftp(self, connect, transport):
        self.assertIsNone(self.storage.sftp)
        self.assertTrue(connect.called)
        connect.reset_mock()
        self.storage._ssh = paramiko.SSHClient()
        self.storage._ssh._transport = transport

        self.storage._sftp = True
        self.assertTrue(self.storage.sftp)
        self.assertFalse(connect.called)

        self.assertTrue(self.storage.sftp)
        self.assertTrue(connect.called)

    def test_override_settings(self):
        with override_settings(SFTP_STORAGE_ROOT='foo1'):
            storage = sftpstorage.SFTPStorage()
            self.assertEqual(storage._root_path, 'foo1')
        with override_settings(SFTP_STORAGE_ROOT='foo2'):
            storage = sftpstorage.SFTPStorage()
            self.assertEqual(storage._root_path, 'foo2')

    def test_override_class_variable(self):
        class MyStorage1(sftpstorage.SFTPStorage):
            root_path = 'foo1'

        storage = MyStorage1()
        self.assertEqual(storage._root_path, 'foo1')

        class MyStorage2(sftpstorage.SFTPStorage):
            root_path = 'foo2'

        storage = MyStorage2()
        self.assertEqual(storage._root_path, 'foo2')

    def test_override_init_argument(self):
        storage = sftpstorage.SFTPStorage(root_path='foo1')
        self.assertEqual(storage._root_path, 'foo1')
        storage = sftpstorage.SFTPStorage(root_path='foo2')
        self.assertEqual(storage._root_path, 'foo2')


class SFTPStorageFileTest(TestCase):
    def setUp(self):
        self.storage = sftpstorage.SFTPStorage(host='foo')
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
