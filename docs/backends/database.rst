Database
========

Class DatabaseStorage can be used with either FileField or ImageField. It can be used to map filenames to database blobs: so you have to use it with a special additional table created manually. The table should contain a pk-column for filenames (better to use the same type that FileField uses: nvarchar(100)), blob field (image type for example) and size field (bigint). You can't just create blob column in the same table, where you defined FileField, since there is no way to find required row in the save() method. Also size field is required to obtain better perfomance (see size() method).

So you can use it with different FileFields and even with different "upload_to" variables used. Thus it implements a kind of root filesystem, where you can define dirs using "upload_to" with FileField and store any files in these dirs.

It uses either settings.DB_FILES_URL or constructor param 'base_url' (see __init__()) to create urls to files. Base url should be mapped to view that provides access to files. To store files in the same table, where FileField is defined you have to define your own field and provide extra argument (e.g. pk) to save().

Raw sql is used for all operations. In constructor or in DB_FILES of settings.py () you should specify a dictionary with db_table, fname_column, blob_column, size_column and 'base_url'. For example I just put to the settings.py the following line::

    DB_FILES = {
        'db_table': 'FILES',
        'fname_column':  'FILE_NAME',
        'blob_column': 'BLOB',
        'size_column': 'SIZE',
        'base_url': 'http://localhost/dbfiles/'
    }

And use it with ImageField as following::

    player_photo = models.ImageField(upload_to="player_photos", storage=DatabaseStorage() )

DatabaseStorage class uses your settings.py file to perform custom connection to your database.

The reason to use custom connection: http://code.djangoproject.com/ticket/5135 Connection string looks like::

    cnxn = pyodbc.connect('DRIVER={SQL Server};SERVER=localhost;DATABASE=testdb;UID=me;PWD=pass')

It's based on pyodbc module, so can be used with any database supported by pyodbc. I've tested it with MS Sql Express 2005.

Note: It returns special path, which should be mapped to special view, which returns requested file::

    def image_view(request, filename):
        import os
        from django.http import HttpResponse
        from django.conf import settings
        from django.utils._os import safe_join
        from filestorage import DatabaseStorage
        from django.core.exceptions import ObjectDoesNotExist

        storage = DatabaseStorage()

        try:
            image_file = storage.open(filename, 'rb')
            file_content = image_file.read()
        except:
            filename = 'no_image.gif'
            path = safe_join(os.path.abspath(settings.MEDIA_ROOT), filename)
            if not os.path.exists(path):
                raise ObjectDoesNotExist
            no_image = open(path, 'rb')
            file_content = no_image.read()

        response = HttpResponse(file_content, mimetype="image/jpeg")
        response['Content-Disposition'] = 'inline; filename=%s'%filename
        return response

.. note:: If filename exist, blob will be overwritten, to change this remove get_available_name(self, name), so Storage.get_available_name(self, name) will be used to generate new filename.
