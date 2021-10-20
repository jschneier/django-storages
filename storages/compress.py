from gzip import GzipFile

from storages.utils import GzipCompressionWrapper


class CompressStorageMixin():
    def _compress_content(self, content):
        """Gzip a given string content."""
        return GzipCompressionWrapper(content)


class CompressedFileMixin():
    def _decompress_file(self, mode, file, mtime=0.0):
        return GzipFile(mode=mode, fileobj=file, mtime=mtime)
