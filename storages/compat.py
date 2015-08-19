from django.utils.six.moves.urllib import parse as urlparse
from django.utils.six import BytesIO
import django

try:
    from django.utils.deconstruct import deconstructible
except ImportError:  # Django 1.7+ migrations
    deconstructible = lambda klass, *args, **kwargs: klass

# Storage only accepts `max_length` in 1.8+
if django.VERSION >= (1, 8):
   from django.core.files.storage import Storage, FileSystemStorage
else:
    from django.core.files.storage import Storage as DjangoStorage
    from django.core.files.storage import FileSystemStorage as DjangoFileSystemStorage

    class StorageMixin(object):
        def save(self, name, content, max_length=None):
            return super(StorageMixin, self).save(name, content)

        def get_available_name(self, name, max_length=None):
            return super(StorageMixin, self).get_available_name(name)

    class Storage(StorageMixin, DjangoStorage):
        pass

    class FileSystemStorage(StorageMixin, DjangoFileSystemStorage):
        pass
