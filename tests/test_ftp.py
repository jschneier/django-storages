import io
from datetime import datetime
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.test import TestCase

from storages.backends import ftp

USER = 'foo'
PASSWORD = 'b@r'
HOST = 'localhost'
PORT = 2121
URL = "ftp://{user}:{passwd}@{host}:{port}/".format(user=USER, passwd=PASSWORD,
                                                    host=HOST, port=PORT)

LIST_FIXTURE = """drwxr-xr-x   2 ftp      nogroup      4096 Jul 27 09:46 dir
-rw-r--r--   1 ftp      nogroup      1024 Jul 27 09:45 fi
-rw-r--r--   1 ftp      nogroup      2048 Jul 27 09:50 fi2"""


def list_retrlines(cmd, func):
    for line in LIST_FIXTURE.splitlines():
        func(line)


class FTPTest(TestCase):
    def setUp(self):
        self.storage = ftp.FTPStorage(location=URL)

    def test_init_no_location(self):
        with self.assertRaises(ImproperlyConfigured):
            ftp.FTPStorage()

    @patch('storages.backends.ftp.setting', return_value=URL)
    def test_init_location_from_setting(self, mock_setting):
        storage = ftp.FTPStorage()
        self.assertTrue(mock_setting.called)
        self.assertEqual(storage.location, URL)

    def test_decode_location(self):
        config = self.storage._decode_location(URL)
        wanted_config = {
            'passwd': 'b@r',
            'host': 'localhost',
            'user': 'foo',
            'active': False,
            'path': '/',
            'port': 2121,
        }
        self.assertEqual(config, wanted_config)
        # Test active FTP
        config = self.storage._decode_location('a'+URL)
        wanted_config = {
            'passwd': 'b@r',
            'host': 'localhost',
            'user': 'foo',
            'active': True,
            'path': '/',
            'port': 2121,
        }
        self.assertEqual(config, wanted_config)

    def test_decode_location_error(self):
        with self.assertRaises(ImproperlyConfigured):
            self.storage._decode_location('foo')
        with self.assertRaises(ImproperlyConfigured):
            self.storage._decode_location('http://foo.pt')
        # TODO: Cannot not provide a port
        # with self.assertRaises(ImproperlyConfigured):
        #     self.storage._decode_location('ftp://')

    @patch('ftplib.FTP')
    def test_start_connection(self, mock_ftp):
        self.storage._start_connection()
        self.assertIsNotNone(self.storage._connection)
        # Start active
        storage = ftp.FTPStorage(location='a'+URL)
        storage._start_connection()

    @patch('ftplib.FTP', **{'return_value.pwd.side_effect': IOError()})
    def test_start_connection_timeout(self, mock_ftp):
        self.storage._start_connection()
        self.assertIsNotNone(self.storage._connection)

    @patch('ftplib.FTP', **{'return_value.connect.side_effect': IOError()})
    def test_start_connection_error(self, mock_ftp):
        with self.assertRaises(ftp.FTPStorageException):
            self.storage._start_connection()

    @patch('ftplib.FTP', **{'return_value.quit.return_value': None})
    def test_disconnect(self, mock_ftp_quit):
        self.storage._start_connection()
        self.storage.disconnect()
        self.assertIsNone(self.storage._connection)

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    def test_mkremdirs(self, mock_ftp):
        self.storage._start_connection()
        self.storage._mkremdirs('foo/bar')

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    def test_mkremdirs_n_subdirectories(self, mock_ftp):
        self.storage._start_connection()
        self.storage._mkremdirs('foo/bar/null')

    @patch('ftplib.FTP', **{
        'return_value.pwd.return_value': 'foo',
        'return_value.storbinary.return_value': None
    })
    def test_put_file(self, mock_ftp):
        self.storage._start_connection()
        self.storage._put_file('foo', File(io.BytesIO(b'foo'), 'foo'))

    @patch('ftplib.FTP', **{
        'return_value.pwd.return_value': 'foo',
        'return_value.storbinary.side_effect': IOError()
    })
    def test_put_file_error(self, mock_ftp):
        self.storage._start_connection()
        with self.assertRaises(ftp.FTPStorageException):
            self.storage._put_file('foo', File(io.BytesIO(b'foo'), 'foo'))

    def test_open(self):
        remote_file = self.storage._open('foo')
        self.assertIsInstance(remote_file, ftp.FTPStorageFile)

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    def test_read(self, mock_ftp):
        self.storage._start_connection()
        self.storage._read('foo')

    @patch('ftplib.FTP', **{'return_value.pwd.side_effect': IOError()})
    def test_read2(self, mock_ftp):
        self.storage._start_connection()
        with self.assertRaises(ftp.FTPStorageException):
            self.storage._read('foo')

    @patch('ftplib.FTP', **{
        'return_value.pwd.return_value': 'foo',
        'return_value.storbinary.return_value': None
    })
    def test_save(self, mock_ftp):
        self.storage._save('foo', File(io.BytesIO(b'foo'), 'foo'))

    @patch('ftplib.FTP', **{'return_value.sendcmd.return_value': '213 20160727094506'})
    def test_modified_time(self, mock_ftp):
        self.storage._start_connection()
        modif_date = self.storage.modified_time('foo')
        self.assertEqual(modif_date, datetime(2016, 7, 27, 9, 45, 6))

    @patch('ftplib.FTP', **{'return_value.sendcmd.return_value': '500'})
    def test_modified_time_error(self, mock_ftp):
        self.storage._start_connection()
        with self.assertRaises(ftp.FTPStorageException):
            self.storage.modified_time('foo')

    @patch('ftplib.FTP', **{'return_value.retrlines': list_retrlines})
    def test_listdir(self, mock_retrlines):
        dirs, files = self.storage.listdir('/')
        self.assertEqual(len(dirs), 1)
        self.assertEqual(dirs, ['dir'])
        self.assertEqual(len(files), 2)
        self.assertEqual(sorted(files), sorted(['fi', 'fi2']))

    @patch('ftplib.FTP', **{'return_value.retrlines.side_effect': IOError()})
    def test_listdir_error(self, mock_ftp):
        with self.assertRaises(ftp.FTPStorageException):
            self.storage.listdir('/')

    @patch('ftplib.FTP', **{'return_value.nlst.return_value': ['foo', 'foo2']})
    def test_exists(self, mock_ftp):
        self.assertTrue(self.storage.exists('foo'))
        self.assertFalse(self.storage.exists('bar'))

    @patch('ftplib.FTP', **{'return_value.nlst.side_effect': IOError()})
    def test_exists_error(self, mock_ftp):
        with self.assertRaises(ftp.FTPStorageException):
            self.storage.exists('foo')

    @patch('ftplib.FTP', **{
        'return_value.delete.return_value': None,
        'return_value.nlst.return_value': ['foo', 'foo2']
    })
    def test_delete(self, mock_ftp):
        self.storage.delete('foo')
        self.assertTrue(mock_ftp.return_value.delete.called)

    @patch('ftplib.FTP', **{'return_value.retrlines': list_retrlines})
    def test_size(self, mock_ftp):
        self.assertEqual(1024, self.storage.size('fi'))
        self.assertEqual(2048, self.storage.size('fi2'))
        self.assertEqual(0, self.storage.size('bar'))

    @patch('ftplib.FTP', **{'return_value.retrlines.side_effect': IOError()})
    def test_size_error(self, mock_ftp):
        self.assertEqual(0, self.storage.size('foo'))

    def test_url(self):
        with self.assertRaises(ValueError):
            self.storage._base_url = None
            self.storage.url('foo')
        self.storage = ftp.FTPStorage(location=URL, base_url='http://foo.bar/')
        self.assertEqual('http://foo.bar/foo', self.storage.url('foo'))


class FTPStorageFileTest(TestCase):
    def setUp(self):
        self.storage = ftp.FTPStorage(location=URL)

    @patch('ftplib.FTP', **{'return_value.retrlines': list_retrlines})
    def test_size(self, mock_ftp):
        file_ = ftp.FTPStorageFile('fi', self.storage, 'wb')
        self.assertEqual(file_.size, 1024)

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    @patch('storages.backends.ftp.FTPStorage._read', return_value=io.BytesIO(b'foo'))
    def test_readlines(self, mock_ftp, mock_storage):
        file_ = ftp.FTPStorageFile('fi', self.storage, 'wb')
        self.assertEqual([b'foo'], file_.readlines())

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    @patch('storages.backends.ftp.FTPStorage._read', return_value=io.BytesIO(b'foo'))
    def test_read(self, mock_ftp, mock_storage):
        file_ = ftp.FTPStorageFile('fi', self.storage, 'wb')
        self.assertEqual(b'foo', file_.read())

    def test_write(self):
        file_ = ftp.FTPStorageFile('fi', self.storage, 'wb')
        file_.write(b'foo')
        file_.seek(0)
        self.assertEqual(file_.file.read(), b'foo')

    @patch('ftplib.FTP', **{'return_value.pwd.return_value': 'foo'})
    @patch('storages.backends.ftp.FTPStorage._read', return_value=io.BytesIO(b'foo'))
    def test_close(self, mock_ftp, mock_storage):
        file_ = ftp.FTPStorageFile('fi', self.storage, 'wb')
        file_.is_dirty = True
        file_.read()
        file_.close()
