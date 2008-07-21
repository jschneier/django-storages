from django.db import models
from django.core.files.storage import default_storage

s3_storage = default_storage

# Write out a file to be used as default content
s3_storage.save('tests/default.txt',  'default content')


class Storage(models.Model):
    def custom_upload_to(self, filename):
        return 'foo'

    normal = models.FileField(storage=s3_storage, upload_to='tests')
    custom = models.FileField(storage=s3_storage, upload_to=custom_upload_to)
    default = models.FileField(storage=s3_storage, upload_to='tests', default='tests/default.txt')
