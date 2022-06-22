from django.core.files.base import ContentFile


class NonSeekableContentFile(ContentFile):

    def open(self, mode=None):
        return self

    def seekable(self):
        return False

    def seek(self, pos, whence=0):
        raise AttributeError()
