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

import sys

from datetime import datetime
from tempfile import SpooledTemporaryFile
from shutil import copyfileobj

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from django.utils._os import safe_join

from storages.utils import setting

from dropbox import Dropbox
from dropbox.files import UploadSessionCursor, CommitInfo
from dropbox.exceptions import ApiError

DATE_FORMAT = '%a, %d %b %Y %X +0000'

# -*- coding: utf-8 -*-


# Print iterations progress
# https://gist.github.com/aubricus/f91fb55dc6ba5557fbab06119420dd6a
def print_progress(iteration, total, prefix='', suffix='', decimals=1,
                   bar_length=100):
    """
    Call in a loop to create terminal progress bar

    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write(
        '\x1b[2K\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix))

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()


class DropBoxStorageException(Exception):
    pass


class DropBoxFile(File):
    def __init__(self, name, storage):
        self.name = name
        self._storage = storage

    @property
    def file(self):
        if not hasattr(self, '_file'):
            response = self._storage.client.files_download(self.name)
            self._file = SpooledTemporaryFile()
            copyfileobj(response, self._file)
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

    def _chunked_upload(self, content, dest_path):
        """use chunked upload session for large files. stolen from
        https://goo.gl/4XV0yT"""

        file_size = len(content)
        content.seek(0)

        upload_session_start_result = (
            self.client.files_upload_session_start(content.read(self.CHUNK_SIZE)))
        cursor = UploadSessionCursor(
            session_id=upload_session_start_result.session_id,
            offset=content.tell())
        commit = CommitInfo(path=dest_path)

        while content.tell() < file_size:
            if ((file_size - content.tell()) <= self.CHUNK_SIZE):
                self.client.files_upload_session_finish(
                    content.read(self.CHUNK_SIZE), cursor, commit)
                print_progress(cursor.offset, file_size)
            else:
                self.client.files_upload_session_append_v2(
                    content.read(self.CHUNK_SIZE), cursor)
                cursor.offset = content.tell()
                print_progress(cursor.offset, file_size)

    def _full_path(self, name):
        if name == '/':
            name = ''
        return safe_join(self.root_path, name)

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
        metadata = self.client.files_get_metadata(full_path)
        for entry in metadata['contents']:
            entry['path'] = entry['path'].replace(full_path, '', 1)
            entry['path'] = entry['path'].replace('/', '', 1)
            if entry['is_dir']:
                directories.append(entry['path'])
            else:
                files.append(entry['path'])
        return directories, files

    def size(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        return metadata['bytes']

    def modified_time(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        mod_time = datetime.strptime(metadata['modified'], DATE_FORMAT)
        return mod_time

    def accessed_time(self, name):
        metadata = self.client.files_get_metadata(self._full_path(name))
        acc_time = datetime.strptime(metadata['client_mtime'], DATE_FORMAT)
        return acc_time

    def url(self, name):
        media = self.client.files_get_temporary_link(self._full_path(name))
        return media['link']

    def _open(self, name, mode='rb'):
        remote_file = DropBoxFile(self._full_path(name), self)
        return remote_file

    def _save(self, name, content):
        file_size = len(content)
        if file_size <= self.CHUNK_SIZE:
            self.client.files_upload(content, self._full_path(name))
        else:
            self._chunked_upload(content, self._full_path(name))
        return name
