import os
import posixpath

from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import Storage


class BaseStorage(Storage):
    def __init__(self, **settings):
        default_settings = self.get_default_settings()

        for name, value in default_settings.items():
            if not hasattr(self, name):
                setattr(self, name, value)

        for name, value in settings.items():
            if name not in default_settings:
                raise ImproperlyConfigured(
                    "Invalid setting '{}' for {}".format(
                        name,
                        self.__class__.__name__,
                    )
                )
            setattr(self, name, value)

    def get_default_settings(self):
        return {}

    def generate_filename(self, filename):
        """
        Validate the filename by calling get_valid_name() and return a filename
        to be passed to the save() method. 
        """
        # `filename` may include a path as returned by FileField.upload_to.
        dirname, filename = os.path.split(filename)
        
        # Use posixpath so it will not use "\\" on Windows
        return posixpath.normpath(posixpath.join(dirname, self.get_valid_name(filename)))
    
