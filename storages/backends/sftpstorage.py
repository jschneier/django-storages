import sys
import warnings

from storages.backends import sftp

warnings.warn(
    "The storages.sftpstorage module has been renamed to storages.sftp. The "
    "old name is still available as an alias but will be removed in "
    "django-storages 2.0.",
    DeprecationWarning
)

sys.modules[__name__] = sftp
