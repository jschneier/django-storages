"""
This is a Custom Storage System for Django with CouchDB backend.
Created by Christian Klein.
(c) Copyright 2009 HUDORA GmbH. All Rights Reserved.
"""
import os
from cStringIO import StringIO
from urlparse import urljoin
from urllib import quote_plus

from django.conf import settings
from django.core.files import File
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured

try:
    import couchdb
except ImportError:
    raise ImproperlyConfigured, "Could not load couchdb dependency.\
    \nSee http://code.google.com/p/couchdb-python/"

DEFAULT_SERVER= getattr(settings, 'COUCHDB_DEFAULT_SERVER', 'http://couchdb.local:5984')
STORAGE_OPTIONS= getattr(settings, 'COUCHDB_STORAGE_OPTIONS', {})


class CouchDBStorage(Storage):
    """
    CouchDBStorage - a Django Storage class for CouchDB.

    The CouchDBStorage can be configured in settings.py, e.g.::
    
        COUCHDB_STORAGE_OPTIONS = {
            'server': "http://example.org", 
            'database': 'database_name'
        }

    Alternatively, the configuration can be passed as a dictionary.
    """
    def __init__(self, **kwargs):
        kwargs.update(STORAGE_OPTIONS)
        self.base_url = kwargs.get('server', DEFAULT_SERVER)
        server = couchdb.client.Server(self.base_url)
        self.db = server[kwargs.get('database')]

    def _put_file(self, name, content):
        self.db[name] = {'size': len(content)}
        self.db.put_attachment(self.db[name], content, filename='content')
        return name

    def get_document(self, name):
        return self.db.get(name)

    def _open(self, name, mode='rb'):
        couchdb_file = CouchDBFile(name, self, mode=mode)
        return couchdb_file

    def _save(self, name, content):
        content.open()
        if hasattr(content, 'chunks'):
            content_str = ''.join(chunk for chunk in content.chunks())
        else:
            content_str = content.read()
        name = name.replace('/', '-')
        return self._put_file(name, content_str)

    def exists(self, name):
        return name in self.db

    def size(self, name):
        doc = self.get_document(name)
        if doc:
            return doc['size']
        return 0

    def url(self, name):
        return urljoin(self.base_url, 
                       os.path.join(quote_plus(self.db.name), 
                       quote_plus(name), 
                       'content'))

    def delete(self, name):
        try:
            del self.db[name]
        except couchdb.client.ResourceNotFound:
            raise IOError("File not found: %s" % name)

    #def listdir(self, name):
    # _all_docs?
    #    pass


class CouchDBFile(File):
    """
    CouchDBFile - a Django File-like class for CouchDB documents.
    """

    def __init__(self, name, storage, mode):
        self._name = name
        self._storage = storage
        self._mode = mode
        self._is_dirty = False

        try:
            self._doc = self._storage.get_document(name)

            tmp, ext = os.path.split(name)
            if ext:
                filename = "content." + ext
            else:
                filename = "content"
            attachment = self._storage.db.get_attachment(self._doc, filename=filename)
            self.file = StringIO(attachment)
        except couchdb.client.ResourceNotFound:
            if 'r' in self._mode:
                raise ValueError("The file cannot be reopened.")
            else:
                self.file = StringIO()
                self._is_dirty = True

    @property
    def size(self):
        return self._doc['size']

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")
        self.file = StringIO(content)
        self._is_dirty = True

    def close(self):
        if self._is_dirty:
            self._storage._put_file(self._name, self.file.getvalue())
        self.file.close()


