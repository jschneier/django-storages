from django.db import models


class SimpleFileModel(models.Model):

    foo_file = models.FileField(upload_to='foo_uploads/')
