import os
import pathlib

from django.core.exceptions import SuspiciousFileOperation
from django.core.files.storage import FileSystemStorage


class FileSystemOverwriteStorage(FileSystemStorage):
    """
    Filesystem storage that never renames files.
    Files uploaded via this storage class will automatically overwrite any files of the same name.
    """

    # Don't throw errors if the file already exists when saving.
    # https://manpages.debian.org/bullseye/manpages-dev/open.2.en.html#O_EXCL
    OS_OPEN_FLAGS = FileSystemStorage.OS_OPEN_FLAGS & ~os.O_EXCL

    # Don't check what files already exist; just use the original name.
    def get_available_name(self, name, max_length=None):
        # Do validate it though (just like FileSystemStorage does)
        name = str(name).replace("\\", "/")
        dir_name, _ = os.path.split(name)
        if ".." in pathlib.PurePath(dir_name).parts:
            raise SuspiciousFileOperation(
                "Detected path traversal attempt in '%s'" % dir_name
            )
        return name
