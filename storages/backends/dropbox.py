# Dropbox storage class for Django pluggable storage system.
# Author: Anthony Monthe <anthony.monthe@gmail.com>
# License: BSD
#
# Usage:
#
# Add below to settings.py:
# DROPBOX_OAUTH2_TOKEN = 'YourOauthToken'
# DROPBOX_ROOT_PATH = '/dir/'

from __future__ import absolute_import

from datetime import datetime
from tempfile import SpooledTemporaryFile
from shutil import copyfileobj

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from django.utils._os import safe_join

from storages.utils import setting

from dropbox.client import DropboxClient
from dropbox.rest import ErrorResponse

DATE_FORMAT = '%a, %d %b %Y %X +0000'


class DropBoxStorageException(Exception):
    pass


class DropBoxFile(File):
    def __init__(self, name, storage):
        self.name = name
        self._storage = storage

    @property
    def file(self):
        if not hasattr(self, '_file'):
            response = self._storage.client.get_file(self.name)
            self._file = SpooledTemporaryFile()
            copyfileobj(response, self._file)
            self._file.seek(0)
        return self._file


@deconstructible
class DropBoxStorage(Storage):
    """DropBox Storage class for Django pluggable storage system."""

    def __init__(self, oauth2_access_token=None, root_path=None):
        oauth2_access_token = oauth2_access_token or setting('DROPBOX_OAUTH2_TOKEN')
        self.root_path = root_path or setting('DROPBOX_ROOT_PATH', '/')
        if oauth2_access_token is None:
            raise ImproperlyConfigured("You must configure a token auth at"
                                       "'settings.DROPBOX_OAUTH2_TOKEN'.")
        self.client = DropboxClient(oauth2_access_token)

    def _full_path(self, name):
        if name == '/':
            name = ''
        return safe_join(self.root_path, name)

    def delete(self, name):
        self.client.file_delete(self._full_path(name))

    def exists(self, name):
        try:
            return bool(self.client.metadata(self._full_path(name)))
        except ErrorResponse:
            return False

    def listdir(self, path):
        directories, files = [], []
        full_path = self._full_path(path)
        metadata = self.client.metadata(full_path)
        for entry in metadata['contents']:
            entry['path'] = entry['path'].replace(full_path, '', 1)
            entry['path'] = entry['path'].replace('/', '', 1)
            if entry['is_dir']:
                directories.append(entry['path'])
            else:
                files.append(entry['path'])
        return directories, files

    def size(self, name):
        metadata = self.client.metadata(self._full_path(name))
        return metadata['bytes']

    def modified_time(self, name):
        metadata = self.client.metadata(self._full_path(name))
        mod_time = datetime.strptime(metadata['modified'], DATE_FORMAT)
        return mod_time

    def accessed_time(self, name):
        metadata = self.client.metadata(self._full_path(name))
        acc_time = datetime.strptime(metadata['client_mtime'], DATE_FORMAT)
        return acc_time

    def url(self, name):
        media = self.client.media(self._full_path(name))
        return media['url']

    def _open(self, name, mode='rb'):
        remote_file = DropBoxFile(self._full_path(name), self)
        return remote_file

    def _save(self, name, content):
        self.client.put_file(self._full_path(name), content)
        return name
