import io
from gzip import GzipFile

from storages.utils import to_bytes


class CompressStorageMixin():
    def _compress_content(self, content):
        """Gzip a given string content."""
        content.seek(0)
        zbuf = io.BytesIO()
        #  The GZIP header has a modification time attribute (see http://www.zlib.org/rfc-gzip.html)
        #  This means each time a file is compressed it changes even if the other contents don't change
        #  For S3 this defeats detection of changes using MD5 sums on gzipped files
        #  Fixing the mtime at 0.0 at compression time avoids this problem
        with GzipFile(mode='wb', fileobj=zbuf, mtime=0.0) as zfile:
            zfile.write(to_bytes(content.read()))
        zbuf.seek(0)
        # We set the file size
        zbuf.size = len(zbuf.getvalue())
        zbuf.seek(0)
        # Boto 2 returned the InMemoryUploadedFile with the file pointer replaced,
        # but Boto 3 seems to have issues with that. No need for fp.name in Boto3
        # so just returning the BytesIO directly
        return zbuf


class CompressFileMixin():
    def _compress_file(self):
        return GzipFile(mode=self._mode, fileobj=self._file, mtime=0.0)
