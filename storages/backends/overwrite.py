import os

from django.conf import settings
from django.core.files.storage import FileSystemStorage

class OverwriteStorage(FileSystemStorage):
    """
    Comes from http://www.djangosnippets.org/snippets/976/
    (even if it already exists in S3Storage for ages)
    
    See also Django #4339, which might add this functionality to core.
    """
    
    def get_available_name(self, name):
        """
        Returns a filename that's free on the target storage system, and
        available for new content to be written to.
        """
        if self.exists(name):
            self.delete(name)
        return name
