# Dropbox storage class for Django pluggable storage system.
# Author: Anthony Monthe <anthony.monthe@gmail.com>
# License: BSD
#
# Usage:
#
# Add below to settings.py:
# DROPBOX_OAUTH2_TOKEN = 'YourOauthToken'

from __future__ import absolute_import

from datetime import datetime

from django.core.files.base import File
from django.core.exceptions import ImproperlyConfigured

from storages.compat import BytesIO, Storage
from storages.utils import setting

from dropbox.client import DropboxClient
from dropbox.rest import ErrorResponse

DATE_FORMAT = '%a, %d %b %Y %X +0000'


class DropBoxStorageException(Exception):
    pass


class DropBoxFile(File):
    def __init__(self, name, storage, mode='rb'):
        self.name = name
        self._storage = storage

    def read(self, num_bytes=None):
        return self._storage._read(self.name, num_bytes=num_bytes)

    def write(self, content):
        self._storage._save(self.name, content)


class DropBoxStorage(Storage):
    """DropBox Storage class for Django pluggable storage system."""

    def __init__(self, oauth2_access_token=setting('DROPBOX_OAUTH2_TOKEN')):
        if oauth2_access_token is None:
            raise ImproperlyConfigured("You must configure a token auth at"
                                       "'settings.DROPBOX_OAUTH2_TOKEN'.")
        self.client = DropboxClient(oauth2_access_token)

    def delete(self, name):
        self.client.file_delete(name)

    def exists(self, name):
        try:
            return bool(self.client.metadata(name))
        except ErrorResponse:
            return False

    def listdir(self, path):
        directories, files = [], []
        metadata = self.client.metadata(path)
        for entry in metadata['contents']:
            if entry['is_dir']:
                directories.append(entry['path'])
            else:
                files.append(entry['path'])
        return directories, files

    def size(self, name):
        metadata = self.client.metadata(name)
        return metadata['bytes']

    def modified_time(self, name):
        metadata = self.client.metadata(name)
        mod_time = datetime.strptime(metadata['modified'], DATE_FORMAT)
        return mod_time

    def accessed_time(self, name):
        metadata = self.client.metadata(name)
        acc_time = datetime.strptime(metadata['client_mtime'], DATE_FORMAT)
        return acc_time

    def url(self, name):
        media = self.client.media(name)
        return media['url']

    def _open(self, name, mode='rb'):
        remote_file = DropBoxFile(name, self)
        return remote_file

    def _save(self, name, content):
        self.client.put_file(name, content)
        return name

    def _read(self, name, num_bytes=None):
        data = self.client.get_file(name)
        return data.read(num_bytes)
