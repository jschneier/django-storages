# DatabaseStorage for django.
# 2009 (c) GameKeeper Gambling Ltd, Ivanov E.
import warnings

from django.conf import settings
from django.core.files import File
from django.core.files.storage import Storage
from django.core.exceptions import ImproperlyConfigured
from django.utils.deconstruct import deconstructible
from django.utils.six import BytesIO
from django.utils.six.moves.urllib import parse as urlparse

try:
    import pyodbc
except ImportError:
    raise ImproperlyConfigured("Could not load pyodbc dependency.\
    \nSee https://github.com/mkleehammer/pyodbc")

REQUIRED_FIELDS = ('db_table', 'fname_column', 'blob_column', 'size_column', 'base_url')
warnings.warn(
    'DatabaseStorage is unmaintained and will be removed in the next version of django-storages.'
    'See https://github.com/jschneier/django-storages/issues/202',
    PendingDeprecationWarning
)


@deconstructible
class DatabaseStorage(Storage):
    """
    Class DatabaseStorage provides storing files in the database.
    """

    def __init__(self, option=settings.DB_FILES):
        """Constructor.

        Constructs object using dictionary either specified in contucotr or
in settings.DB_FILES.

        @param option dictionary with 'db_table', 'fname_column',
'blob_column', 'size_column', 'base_url'  keys.

        option['db_table']
            Table to work with.
        option['fname_column']
            Column in the 'db_table' containing filenames (filenames can
contain pathes). Values should be the same as where FileField keeps
filenames.
            It is used to map filename to blob_column. In sql it's simply
used in where clause.
        option['blob_column']
            Blob column (for example 'image' type), created manually in the
'db_table', used to store image.
        option['size_column']
            Column to store file size. Used for optimization of size()
method (another way is to open file and get size)
        option['base_url']
            Url prefix used with filenames. Should be mapped to the view,
that returns an image as result.
        """

        if not option or not all([field in option for field in REQUIRED_FIELDS]):
            raise ValueError("You didn't specify required options")

        self.db_table = option['db_table']
        self.fname_column = option['fname_column']
        self.blob_column = option['blob_column']
        self.size_column = option['size_column']
        self.base_url = option['base_url']

        #get database settings
        self.DATABASE_ODBC_DRIVER = settings.DATABASE_ODBC_DRIVER
        self.DATABASE_NAME = settings.DATABASE_NAME
        self.DATABASE_USER = settings.DATABASE_USER
        self.DATABASE_PASSWORD = settings.DATABASE_PASSWORD
        self.DATABASE_HOST = settings.DATABASE_HOST

        self.connection = pyodbc.connect('DRIVER=%s;SERVER=%s;DATABASE=%s;UID=%s;PWD=%s'%(self.DATABASE_ODBC_DRIVER,self.DATABASE_HOST,self.DATABASE_NAME,
                                                                                          self.DATABASE_USER, self.DATABASE_PASSWORD) )
        self.cursor = self.connection.cursor()

    def _open(self, name, mode='rb'):
        """Open a file from database.

        @param name filename or relative path to file based on base_url. path should contain only "/", but not "\". Apache sends pathes with "/".
        If there is no such file in the db, returs None
        """

        assert mode == 'rb', "You've tried to open binary file without specifying binary mode! You specified: %s"%mode

        row = self.cursor.execute("SELECT %s from %s where %s = '%s'"%(self.blob_column,self.db_table,self.fname_column,name) ).fetchone()
        if row is None:
            return None
        inMemFile = BytesIO(row[0])
        inMemFile.name = name
        inMemFile.mode = mode

        retFile = File(inMemFile)
        return retFile

    def _save(self, name, content):
        """Save 'content' as file named 'name'.

        @note '\' in path will be converted to '/'.
        """

        name = name.replace('\\', '/')
        binary = pyodbc.Binary(content.read())
        size = len(binary)

        #todo: check result and do something (exception?) if failed.
        if self.exists(name):
            self.cursor.execute("UPDATE %s SET %s = ?, %s = ? WHERE %s = '%s'"%(self.db_table,self.blob_column,self.size_column,self.fname_column,name),
                                 (binary, size)  )
        else:
            self.cursor.execute("INSERT INTO %s VALUES(?, ?, ?)"%(self.db_table), (name, binary, size)  )
        self.connection.commit()
        return name

    def exists(self, name):
        row = self.cursor.execute("SELECT %s from %s where %s = '%s'"%(self.fname_column,self.db_table,self.fname_column,name)).fetchone()
        return row is not None

    def get_available_name(self, name, max_length=None):
        return name

    def delete(self, name):
        if self.exists(name):
            self.cursor.execute("DELETE FROM %s WHERE %s = '%s'"%(self.db_table,self.fname_column,name))
            self.connection.commit()

    def url(self, name):
        if self.base_url is None:
            raise ValueError("This file is not accessible via a URL.")
        return urlparse.urljoin(self.base_url, name).replace('\\', '/')

    def size(self, name):
        row = self.cursor.execute("SELECT %s from %s where %s = '%s'"%(self.size_column,self.db_table,self.fname_column,name)).fetchone()
        if row is None:
            return 0
        else:
            return int(row[0])
