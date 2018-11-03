from django.core.files.base import File
from django.core.files.storage import Storage

class BaseFile(File):
    pass

class BaseStorage(Storage):
    def pre_save(name, content):
        return name, content