import os

from django.conf import settings
from django.core.files.storage import FileSystemStorage

__doc__ = """
I needed to efficiently create a mirror of a directory tree (so that 
"origin pull" CDNs can automatically pull files). The trick was that 
some files could be modified, and some could be identical to the original. 
Of course it doesn't make sense to store the exact same data twice on the 
file system. So I created SymlinkOrCopyStorage.

SymlinkOrCopyStorage allows you to symlink a file when it's identical to 
the original file and to copy the file if it's modified.
Of course, it's impossible to know if a file is modified just by looking 
at the file, without knowing what the original file was.
That's what the symlinkWithin parameter is for. It accepts one or more paths 
(if multiple, they should be concatenated using a colon (:)). 
Files that will be saved using SymlinkOrCopyStorage are then checked on their 
location: if they are within one of the symlink_within directories, 
they will be symlinked, otherwise they will be copied.

The rationale is that unmodified files will exist in their original location, 
e.g. /htdocs/example.com/image.jpg and modified files will be stored in 
a temporary directory, e.g. /tmp/image.jpg.
"""

class SymlinkOrCopyStorage(FileSystemStorage):
    """Stores symlinks to files instead of actual files whenever possible
    
    When a file that's being saved is currently stored in the symlink_within
    directory, then symlink the file. Otherwise, copy the file.
    """
    def __init__(self, location=settings.MEDIA_ROOT, base_url=settings.MEDIA_URL, 
            symlink_within=None):
        super(SymlinkOrCopyStorage, self).__init__(location, base_url)
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
            super(SymlinkOrCopyStorage, self)._save(name, content)

        return name
