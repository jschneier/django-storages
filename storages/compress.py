import io
from gzip import GzipFile

from storages.utils import GzipCompressionWrapper


class CompressStorageMixin():
    def _compress_content(self, content):
        """Gzip a given string content."""
        return GzipCompressionWrapper(content)


class CompressFileMixin():
    def _compress_file(self):
        return GzipFile(mode=self._mode, fileobj=self._file, mtime=0.0)
