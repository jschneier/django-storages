
import tempfile

from django.db import models
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage as s3_storage
from django.core.cache import cache

# Write out a file to be used as default content
s3_storage.save('tests/default.txt', ContentFile('default content'))

class MyStorage(models.Model):
    def custom_upload_to(self, filename):
        return 'foo'

    def random_upload_to(self, filename):
        # This returns a different result each time,
        # to make sure it only gets called once.
        import random
        return '%s/%s' % (random.randint(100, 999), filename)

    normal = models.FileField(storage=s3_storage, upload_to='tests')
    custom = models.FileField(storage=s3_storage, upload_to=custom_upload_to)
    random = models.FileField(storage=s3_storage, upload_to=random_upload_to)
    default = models.FileField(storage=s3_storage, upload_to='tests', default='tests/default.txt')
