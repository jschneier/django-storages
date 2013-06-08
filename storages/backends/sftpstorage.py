# SFTP storage backend for Django.
# Author: Brent Tubbs <brent.tubbs@gmail.com>
# License: MIT
#
# Modeled on the FTP storage by Rafal Jonca <jonca.rafal@gmail.com>
#
# Settings:
#
# SFTP_STORAGE_HOST - The hostname where you want the files to be saved.
#
# SFTP_STORAGE_ROOT - The root directory on the remote host into which files
# should be placed.  Should work the same way that STATIC_ROOT works for local
# files.  Must include a trailing slash.
#
# SFTP_STORAGE_PARAMS (Optional) - A dictionary containing connection
# parameters to be passed as keyword arguments to
# paramiko.SSHClient().connect() (do not include hostname here).  See
# http://www.lag.net/paramiko/docs/paramiko.SSHClient-class.html#connect for
# details
#
# SFTP_STORAGE_INTERACTIVE (Optional) - A boolean indicating whether to prompt
# for a password if the connection cannot be made using keys, and there is not
# already a password in SFTP_STORAGE_PARAMS.  You can set this to True to
# enable interactive login when running 'manage.py collectstatic', for example.
#
#   DO NOT set SFTP_STORAGE_INTERACTIVE to True if you are using this storage
#   for files being uploaded to your site by users, because you'll have no way
#   to enter the password when they submit the form..
#
# SFTP_STORAGE_FILE_MODE (Optional) - A bitmask for setting permissions on
# newly-created files.  See http://docs.python.org/library/os.html#os.chmod for
# acceptable values.
#
# SFTP_STORAGE_DIR_MODE (Optional) - A bitmask for setting permissions on
# newly-created directories.  See
# http://docs.python.org/library/os.html#os.chmod for acceptable values.
#
#   Hint: if you start the mode number with a 0 you can express it in octal
#   just like you would when doing "chmod 775 myfile" from bash.
#
# SFTP_STORAGE_UID (Optional) - uid of the account that should be set as owner
# of the files on the remote host.  You have to be root to set this.
#
# SFTP_STORAGE_GID (Optional) - gid of the group that should be set on the
# files on the remote host.  You have to be a member of the group to set this.
# SFTP_KNOWN_HOST_FILE (Optional) - absolute path of know host file, if it isn't
# set "~/.ssh/known_hosts" will be used


import getpass
import os
import paramiko
import posixpath
import stat
import urlparse
from datetime import datetime

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO  # noqa


class SFTPStorage(Storage):

    def __init__(self):
        self._host = settings.SFTP_STORAGE_HOST

        # if present, settings.SFTP_STORAGE_PARAMS should be a dict with params
        # matching the keyword arguments to paramiko.SSHClient().connect().  So
        # you can put username/password there.  Or you can omit all that if
        # you're using keys.
        self._params = getattr(settings, 'SFTP_STORAGE_PARAMS', {})
        self._interactive = getattr(settings, 'SFTP_STORAGE_INTERACTIVE',
                                    False)
        self._file_mode = getattr(settings, 'SFTP_STORAGE_FILE_MODE', None)
        self._dir_mode = getattr(settings, 'SFTP_STORAGE_DIR_MODE', None)

        self._uid = getattr(settings, 'SFTP_STORAGE_UID', None)
        self._gid = getattr(settings, 'SFTP_STORAGE_GID', None)
        self._known_host_file = getattr(settings, 'SFTP_KNOWN_HOST_FILE', None)

        self._root_path = settings.SFTP_STORAGE_ROOT
        self._base_url = settings.MEDIA_URL

        # for now it's all posix paths.  Maybe someday we'll support figuring
        # out if the remote host is windows.
        self._pathmod = posixpath

    def _connect(self):
        self._ssh = paramiko.SSHClient()

        if self._known_host_file is not None:
            self._ssh.load_host_keys(self._known_host_file)
        else:
            # automatically add host keys from current user.
            self._ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))

        # and automatically add new host keys for hosts we haven't seen before.
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._ssh.connect(self._host, **self._params)
        except paramiko.AuthenticationException, e:
            if self._interactive and 'password' not in self._params:
                # If authentication has failed, and we haven't already tried
                # username/password, and configuration allows it, then try
                # again with username/password.
                if 'username' not in self._params:
                    self._params['username'] = getpass.getuser()
                self._params['password'] = getpass.getpass()
                self._connect()
            else:
                raise paramiko.AuthenticationException, e
        except Exception, e:
            print e

        if not hasattr(self, '_sftp'):
            self._sftp = self._ssh.open_sftp()

    @property
    def sftp(self):
        """Lazy SFTP connection"""
        if not hasattr(self, '_sftp'):
            self._connect()
        return self._sftp

    def _join(self, *args):
        # Use the path module for the remote host type to join a path together
        return self._pathmod.join(*args)

    def _remote_path(self, name):
        return self._join(self._root_path, name)

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
        parent = self._pathmod.dirname(path)
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
        dirname = self._pathmod.dirname(path)
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
        remote_path = self._remote_path(name)
        self.sftp.remove(remote_path)

    def exists(self, name):
        # Try to retrieve file info.  Return true on success, false on failure.
        remote_path = self._remote_path(name)
        try:
            self.sftp.stat(remote_path)
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
        self._name = name
        self._storage = storage
        self._mode = mode
        self._is_dirty = False
        self.file = StringIO()
        self._is_read = False

    @property
    def size(self):
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self._name)
        return self._size

    def read(self, num_bytes=None):
        if not self._is_read:
            self.file = self._storage._read(self._name)
            self._is_read = True

        return self.file.read(num_bytes)

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True
        self._is_read = True

    def close(self):
        if self._is_dirty:
            self._storage._save(self._name, self.file.getvalue())
        self.file.close()
