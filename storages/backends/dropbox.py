# Dropbox storage class for Django pluggable storage system.
# Author: Anthony Monthe <anthony.monthe@gmail.com>
# License: BSD
#
# Usage:
#
# Add below to settings.py:
# DROPBOX_OAUTH2_TOKEN = 'YourOauthToken'
# DROPBOX_ROOT_PATH = '/dir/'

from __future__ import absolute_import, unicode_literals

from tempfile import NamedTemporaryFile

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from dropbox import Dropbox
from dropbox.exceptions import ApiError
from dropbox.files import CommitInfo, FolderMetadata, UploadSessionCursor

from storages.utils import setting

try:
    from pathlib import PurePosixPath
except ImportError:  # Python 3.3 and below
    from pathlib2 import PurePosixPath


class DropBoxStorageException(Exception):
    pass


class DropBoxFile(File):
    def __init__(self, name, storage):
        self.name = name
        self._storage = storage

    @property
    def file(self):
        if not hasattr(self, '_file'):
            self._file = NamedTemporaryFile()
            self._storage.client.files_download_to_file(self._file.name,
                                                        self.name)
            self._file.seek(0)

        return self._file


@deconstructible
class DropBoxStorage(Storage):
    """DropBox Storage class for Django pluggable storage system."""

    CHUNK_SIZE = 4 * 1024 * 1024

    def __init__(self, oauth2_access_token=None, root_path=None):
        oauth2_access_token = oauth2_access_token or setting('DROPBOX_OAUTH2_TOKEN')
        self.root_path = root_path or setting('DROPBOX_ROOT_PATH', '/')
        if oauth2_access_token is None:
            raise ImproperlyConfigured("You must configure a token auth at"
                                       "'settings.DROPBOX_OAUTH2_TOKEN'.")
        self.client = Dropbox(oauth2_access_token)

    def _full_path(self, path):
        path = PurePosixPath(self.root_path) / path
        path = str(path)

        if path == '/':
            path = ''

        return path

    def delete(self, name):
        self.client.files_delete(self._full_path(name))

    def exists(self, name):
        try:
            return bool(self.client.files_get_metadata(self._full_path(name)))
        except ApiError:
            return False

    def listdir(self, path):
        directories, files = [], []
        full_path = self._full_path(path)
        result = self.client.files_list_folder(full_path)

        for entry in result.entries:
            if isinstance(entry, FolderMetadata):
                directories.append(entry.name)
            else:
                files.append(entry.name)

        assert not result.has_more, "FIXME: Not implemented!"

        return directories, files

    def size(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        return metadata.size

    def modified_time(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        return metadata.server_modified

    def accessed_time(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        # Note to the unwary, this is actually an mtime
        return metadata.client_modified

    def url(self, name):
        try:
            media = self.client.files_get_temporary_link(self._full_path(name))
            return media.link
        except ApiError:
            raise ValueError("This file is not accessible via a URL.")

    def _open(self, name, mode='rb'):
        return DropBoxFile(self._full_path(name), self)

    def _save(self, name, content):
        try:
            content.open()

            if content.size <= self.CHUNK_SIZE:
                self.client.files_upload(content.read(), self._full_path(name))
            else:
                self._chunked_upload(content, self._full_path(name))

        finally:
            content.close()

        return name

    def _chunked_upload(self, content, dest_path):
        upload_session = self.client.files_upload_session_start(
            content.read(self.CHUNK_SIZE)
        )
        cursor = UploadSessionCursor(
            session_id=upload_session.session_id,
            offset=content.tell()
        )
        commit = CommitInfo(path=dest_path)

        while content.tell() < content.size:
            if (content.size - content.tell()) <= self.CHUNK_SIZE:
                self.client.files_upload_session_finish(
                    content.read(self.CHUNK_SIZE), cursor, commit
                )
            else:
                self.client.files_upload_session_append_v2(
                    content.read(self.CHUNK_SIZE), cursor
                )
                cursor.offset = content.tell()
