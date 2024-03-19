Filesystem
==========

django-storages contains an alternative filesystem storage backend.

Unlike Django's builtin filesystem storage, this one always overwrites files of the same name, and never renames files.


Usage
*****

::

    from storages.backends.filesystem import FileSystemOverwriteStorage
    
    storage = FileSystemOverwriteStorage(location='/media/photos')
    storage.save("myfile.txt", ContentFile("content 1"))
    
    # This will overwrite the previous file, *not* create a new file.
    storage.save("myfile.txt", ContentFile("content 2"))

