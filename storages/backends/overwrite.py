import warnings

from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible

warnings.warn(
    'OverwriteStorage is unmaintained and will be removed in the next django-storages version.'
    'See https://github.com/jschneier/django-storages/issues/202',
    PendingDeprecationWarning
)


@deconstructible
class OverwriteStorage(FileSystemStorage):
    """
    Comes from http://www.djangosnippets.org/snippets/976/
    (even if it already exists in S3Storage for ages)

    See also Django #4339, which might add this functionality to core.
    """

    def get_available_name(self, name, max_length=None):
        """
        Returns a filename that's free on the target storage system, and
        available for new content to be written to.
        """
        if self.exists(name):
            self.delete(name)
        return name
