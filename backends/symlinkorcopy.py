import os
import os.path

from django.conf import settings
from django.core.files.storage import FileSystemStorage


class SymlinkOrCopyStorage(FileSystemStorage):
    """Stores symlinks to files instead of actual files whenever possible
    
    When a file that's being saved is currently stored in the symlinkWithin
    directory, then symlink the file. Otherwise, copy the file.
    """
    def __init__(self, location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL, 
            symlink_within=None):
        super(FileSystemStorage, self).__init__(location, base_url)
        self.symlink_within = symlink_within.split(":")

    def _save(self, name, content):
        full_path_dst = self.path(name)

        directory = os.path.dirname(full_path_dst)
        if not os.path.exists(directory):
            os.makedirs(directory)
        elif not os.path.isdir(directory):
            raise IOError("%s exists and is not a directory." % directory)

        full_path_src = os.path.abspath(content.name)

        symlinked = False
        # Only symlink if the current platform supports it.
        if getattr(os, "symlink", False):
            for path in self.symlink_within:
                if full_path_src.startswith(path):
                    os.symlink(full_path_src, full_path_dst)
                    symlinked = True
                    break

        if not symlinked:
            super(FileSystemStorage, self)._save(name, content)

        return name
