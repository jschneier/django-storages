# SFTP storage backend for Django.
# Author: Brent Tubbs <brent.tubbs@gmail.com>
# License: MIT
#
# Modeled on the FTP storage by Rafal Jonca <jonca.rafal@gmail.com>
from __future__ import print_function

import getpass
import io
import os
import posixpath
import stat
from datetime import datetime

import paramiko
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

from storages.utils import setting

try:
    from django.utils.six.moves.urllib import parse as urlparse
except ImportError:
    from urllib import parse as urlparse


@deconstructible
class SFTPStorage(Storage):

    def __init__(self, host=None, params=None, interactive=None, file_mode=None,
                 dir_mode=None, uid=None, gid=None, known_host_file=None,
                 root_path=None, base_url=None):
        self._host = host or setting('SFTP_STORAGE_HOST')

        self._params = params or setting('SFTP_STORAGE_PARAMS', {})
        self._interactive = setting('SFTP_STORAGE_INTERACTIVE', False) \
            if interactive is None else interactive
        self._file_mode = setting('SFTP_STORAGE_FILE_MODE') \
            if file_mode is None else file_mode
        self._dir_mode = setting('SFTP_STORAGE_DIR_MODE') if \
            dir_mode is None else dir_mode

        self._uid = setting('SFTP_STORAGE_UID') if uid is None else uid
        self._gid = setting('SFTP_STORAGE_GID') if gid is None else gid
        self._known_host_file = setting('SFTP_KNOWN_HOST_FILE') \
            if known_host_file is None else known_host_file

        self._root_path = setting('SFTP_STORAGE_ROOT', '') \
            if root_path is None else root_path
        self._base_url = setting('MEDIA_URL') if base_url is None else base_url

        self._sftp = None

    def _connect(self):
        self._ssh = paramiko.SSHClient()

        known_host_file = self._known_host_file or os.path.expanduser(
            os.path.join("~", ".ssh", "known_hosts")
        )

        if os.path.exists(known_host_file):
            self._ssh.load_host_keys(known_host_file)

        # and automatically add new host keys for hosts we haven't seen before.
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._ssh.connect(self._host, **self._params)
        except paramiko.AuthenticationException as e:
            if self._interactive and 'password' not in self._params:
                # If authentication has failed, and we haven't already tried
                # username/password, and configuration allows it, then try
                # again with username/password.
                if 'username' not in self._params:
                    self._params['username'] = getpass.getuser()
                self._params['password'] = getpass.getpass()
                self._connect()
            else:
                raise paramiko.AuthenticationException(e)
        except Exception as e:
            print(e)

        if self._ssh.get_transport():
            self._sftp = self._ssh.open_sftp()

    @property
    def sftp(self):
        """Lazy SFTP connection"""
        if not self._sftp or not self._ssh.get_transport().is_active():
            self._connect()
        return self._sftp

    def _remote_path(self, name):
        return posixpath.join(self._root_path, name)

    def _open(self, name, mode='rb'):
        return SFTPStorageFile(name, self, mode)

    def _read(self, name):
        remote_path = self._remote_path(name)
        return self.sftp.open(remote_path, 'rb')

    def _chown(self, path, uid=None, gid=None):
        """Set uid and/or gid for file at path."""
        # Paramiko's chown requires both uid and gid, so look them up first if
        # we're only supposed to set one.
        if uid is None or gid is None:
            attr = self.sftp.stat(path)
            uid = uid or attr.st_uid
            gid = gid or attr.st_gid
        self.sftp.chown(path, uid, gid)

    def _mkdir(self, path):
        """Create directory, recursing up to create parent dirs if
        necessary."""
        parent = posixpath.dirname(path)
        if not self.exists(parent):
            self._mkdir(parent)
        self.sftp.mkdir(path)

        if self._dir_mode is not None:
            self.sftp.chmod(path, self._dir_mode)

        if self._uid or self._gid:
            self._chown(path, uid=self._uid, gid=self._gid)

    def _save(self, name, content):
        """Save file via SFTP."""
        content.open()
        path = self._remote_path(name)
        dirname = posixpath.dirname(path)
        if not self.exists(dirname):
            self._mkdir(dirname)

        f = self.sftp.open(path, 'wb')
        f.write(content.file.read())
        f.close()

        # set file permissions if configured
        if self._file_mode is not None:
            self.sftp.chmod(path, self._file_mode)
        if self._uid or self._gid:
            self._chown(path, uid=self._uid, gid=self._gid)
        return name

    def delete(self, name):
        try:
            self.sftp.remove(self._remote_path(name))
        except IOError:
            pass

    def exists(self, name):
        try:
            self.sftp.stat(self._remote_path(name))
            return True
        except IOError:
            return False

    def _isdir_attr(self, item):
        # Return whether an item in sftp.listdir_attr results is a directory
        if item.st_mode is not None:
            return stat.S_IFMT(item.st_mode) == stat.S_IFDIR
        else:
            return False

    def listdir(self, path):
        remote_path = self._remote_path(path)
        dirs, files = [], []
        for item in self.sftp.listdir_attr(remote_path):
            if self._isdir_attr(item):
                dirs.append(item.filename)
            else:
                files.append(item.filename)
        return dirs, files

    def size(self, name):
        remote_path = self._remote_path(name)
        return self.sftp.stat(remote_path).st_size

    def accessed_time(self, name):
        remote_path = self._remote_path(name)
        utime = self.sftp.stat(remote_path).st_atime
        return datetime.fromtimestamp(utime)

    def modified_time(self, name):
        remote_path = self._remote_path(name)
        utime = self.sftp.stat(remote_path).st_mtime
        return datetime.fromtimestamp(utime)

    def url(self, name):
        if self._base_url is None:
            raise ValueError("This file is not accessible via a URL.")
        return urlparse.urljoin(self._base_url, name).replace('\\', '/')


class SFTPStorageFile(File):
    def __init__(self, name, storage, mode):
        self.name = name
        self.mode = mode
        self.file = io.BytesIO()
        self._storage = storage
        self._is_read = False
        self._is_dirty = False

    @property
    def size(self):
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self.name)
        return self._size

    def read(self, num_bytes=None):
        if not self._is_read:
            self.file = self._storage._read(self.name)
            self._is_read = True

        return self.file.read(num_bytes)

    def write(self, content):
        if 'w' not in self.mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = io.BytesIO(content)
        self._is_dirty = True
        self._is_read = True

    def open(self, mode=None):
        if not self.closed:
            self.seek(0)
        elif self.name and self._storage.exists(self.name):
            self.file = self._storage._open(self.name, mode or self.mode)
        else:
            raise ValueError("The file cannot be reopened.")

    def close(self):
        if self._is_dirty:
            self._storage._save(self.name, self)
        self.file.close()
