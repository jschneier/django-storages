import os, hashlib, errno

from django.core.files.storage import FileSystemStorage
from django.utils.encoding import force_unicode

class HashPathStorage(FileSystemStorage):
    """
    Creates a hash from the uploaded file to build the path.
    """

    def save(self, name, content):
        # Get the content name if name is not given
        if name is None: name = content.name

        # Get the SHA1 hash of the uploaded file
        sha1 = hashlib.sha1()
        for chunk in content.chunks():
            sha1.update(chunk)
        sha1sum = sha1.hexdigest()

        # Build the new path and split it into directory and filename
        name = os.path.join(os.path.split(name)[0], sha1sum[:1], sha1sum[1:2], sha1sum)
        dir_name, file_name = os.path.split(name)

        # Return the name if the file is already there
        if self.exists(name):
            return name

        # Try to create the directory relative to location specified in __init__
        try:
            os.makedirs(os.path.join(self.location, dir_name))
        except OSError, e:
            if e.errno is not errno.EEXIST:
                raise e

        # Save the file
        name = self._save(name, content)

        # Store filenames with forward slashes, even on Windows
        return force_unicode(name.replace('\\', '/'))
