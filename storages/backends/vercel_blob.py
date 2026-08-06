import mimetypes
import posixpath
from tempfile import SpooledTemporaryFile

from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import SuspiciousOperation
from django.core.files.base import File
from django.utils.deconstruct import deconstructible

from storages.base import BaseStorage
from storages.utils import clean_name
from storages.utils import get_available_overwrite_name
from storages.utils import lookup_env
from storages.utils import safe_join
from storages.utils import setting

try:
    import vercel.blob as vblob
    from vercel.blob.errors import BlobError
    from vercel.blob.errors import BlobNotFoundError
except ImportError as e:
    raise ImproperlyConfigured(
        "Could not load Vercel Blob bindings. "
        "Install with: pip install django-storages[vercel-blob]\n%s" % e
    )


def _get_content_type(name, content=None):
    """Return the MIME type for *name*, preferring *content.content_type*."""
    ct = getattr(content, "content_type", None)
    if not ct:
        try:
            ct = content.file.content_type
        except AttributeError:
            pass
    if not ct:
        ct, _ = mimetypes.guess_type(name)
    return ct


@deconstructible
class VercelBlobFile(File):
    """File-like object returned by :class:`VercelBlobStorage`.

    Reads are fully buffered into a :class:`~tempfile.SpooledTemporaryFile`
    on first access.  Writes are buffered locally and flushed to Vercel Blob
    when :meth:`close` is called.
    """

    def __init__(self, name, mode, storage):
        self.name = name
        self._mode = mode
        self._storage = storage
        self._is_dirty = False
        self._file = None

    def _get_file(self):
        if self._file is None:
            self._file = SpooledTemporaryFile(
                max_size=self._storage.max_memory_size,
                suffix=".VercelBlobFile",
                dir=setting("FILE_UPLOAD_TEMP_DIR"),
            )
            if "r" in self._mode:
                blob_path = self._storage._get_blob_path(self.name)
                result = vblob.get(
                    blob_path,
                    access=self._storage.access,
                    token=self._storage.token,
                )
                self._file.write(result.content)
                self._file.seek(0)
        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, num_bytes=None):
        if "r" not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        if num_bytes is None:
            return super().read()
        return super().read(num_bytes)

    def write(self, content):
        if "w" not in self._mode and "+" not in self._mode and "a" not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        return super().write(content)

    def close(self):
        if self._file is None:
            return
        if self._is_dirty:
            self._file.seek(0)
            self._storage._save(self.name, self._file)
            self._is_dirty = False
        self._file.close()
        self._file = None


@deconstructible
class VercelBlobStorage(BaseStorage):
    """Django storage backend for `Vercel Blob`_.

    Uses the official ``vercel-py`` SDK to store files on Vercel Blob.
    Both ``"public"`` and ``"private"`` access modes are supported.

    .. _Vercel Blob: https://vercel.com/docs/storage/vercel-blob

    .. note::

        Vercel Blob does **not** support presigned or time-limited URLs.
        For private blobs, :meth:`url` returns the raw private blob URL
        which requires an ``Authorization: Bearer <token>`` header to
        access.  Serve private files through a Django view that proxies
        the download.

    .. note::

        The ``vercel`` package requires **Python 3.10 or newer**.
    """

    def get_default_settings(self):
        return {
            "token": setting(
                "VERCEL_BLOB_TOKEN",
                lookup_env(["BLOB_READ_WRITE_TOKEN", "VERCEL_BLOB_READ_WRITE_TOKEN"]),
            ),
            "access": setting("VERCEL_BLOB_ACCESS", "public"),
            "location": setting("VERCEL_BLOB_LOCATION", ""),
            "file_overwrite": setting("VERCEL_BLOB_FILE_OVERWRITE", True),
            "default_content_type": setting(
                "VERCEL_BLOB_DEFAULT_CONTENT_TYPE", "application/octet-stream"
            ),
            "max_memory_size": setting("VERCEL_BLOB_MAX_MEMORY_SIZE", 0),
        }

    def __init__(self, **settings):
        super().__init__(**settings)

        if not self.token:
            raise ImproperlyConfigured(
                "VercelBlobStorage requires an authentication token. "
                "Set VERCEL_BLOB_TOKEN in your Django settings, or one of the "
                "BLOB_READ_WRITE_TOKEN / VERCEL_BLOB_READ_WRITE_TOKEN "
                "environment variables."
            )

        if self.access not in ("public", "private"):
            raise ImproperlyConfigured(
                "VERCEL_BLOB_ACCESS must be 'public' or 'private', got %r." % self.access
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_name(self, name):
        """Join *name* with the configured ``location`` prefix."""
        try:
            return safe_join(self.location, name)
        except ValueError:
            raise SuspiciousOperation("Attempted access to '%s' denied." % name)

    def _get_blob_path(self, name):
        return self._normalize_name(clean_name(name))

    def _get_content_type(self, name, content=None):
        ct = _get_content_type(name, content)
        return ct or self.default_content_type

    def _build_url(self, blob_path):
        """Construct the canonical Vercel Blob URL without a network call.

        The URL pattern is::

            https://{storeId}.{access}.blob.vercel-storage.com/{pathname}

        The store ID is the fourth underscore-delimited segment of the
        bearer token (``vercel_blob_rw_{storeId}_{hash}``).  If it cannot
        be extracted a :func:`~vercel.blob.head` call is used as a fallback.
        """
        store_id = ""
        try:
            parts = self.token.split("_")
            store_id = parts[3] if len(parts) > 3 else ""
        except Exception:
            pass

        path = blob_path.lstrip("/")

        if store_id:
            return "https://{store_id}.{access}.blob.vercel-storage.com/{path}".format(
                store_id=store_id,
                access=self.access,
                path=path,
            )

        # Fallback: ask the API for the canonical URL.
        result = vblob.head(blob_path, token=self.token)
        return result.url

    # ------------------------------------------------------------------
    # Django Storage interface
    # ------------------------------------------------------------------

    def _open(self, name, mode="rb"):
        if "w" in mode or "a" in mode:
            # Write / append modes: defer all I/O until close().
            return VercelBlobFile(name, mode, self)

        # Read mode: verify the object exists before returning a file handle.
        blob_path = self._get_blob_path(name)
        try:
            vblob.head(blob_path, token=self.token)
        except BlobNotFoundError:
            raise FileNotFoundError("File does not exist: %s" % name)
        return VercelBlobFile(name, mode, self)

    def _save(self, name, content):
        cleaned_name = clean_name(name)
        blob_path = self._normalize_name(cleaned_name)
        content_type = self._get_content_type(cleaned_name, content)

        if hasattr(content, "seek") and callable(content.seek):
            content.seek(0)

        vblob.put(
            blob_path,
            content,
            access=self.access,
            content_type=content_type,
            overwrite=self.file_overwrite,
            token=self.token,
        )
        return cleaned_name

    def delete(self, name):
        blob_path = self._get_blob_path(name)
        try:
            vblob.delete(blob_path, token=self.token)
        except BlobNotFoundError:
            pass  # Deleting a non-existent object is not an error.

    def exists(self, name):
        blob_path = self._get_blob_path(name)
        try:
            vblob.head(blob_path, token=self.token)
            return True
        except BlobNotFoundError:
            return False

    def listdir(self, path):
        """List files and sub-directories under *path*.

        Returns a ``(directories, files)`` tuple.  Uses the Vercel Blob
        list API with ``mode="folded"`` so that common path prefixes are
        collapsed into virtual folder entries.

        .. note::
            The list API is paginated; this method fetches all pages.
            Stores with a very large number of objects may incur noticeable
            latency.
        """
        prefix = self._normalize_name(clean_name(path))
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        directories = []
        files = []
        cursor = None

        while True:
            result = vblob.list_objects(
                prefix=prefix or None,
                mode="folded",
                cursor=cursor,
                token=self.token,
            )

            for item in result.blobs:
                rel = (
                    posixpath.relpath(item.pathname, prefix)
                    if prefix
                    else item.pathname
                )
                if "/" not in rel:
                    files.append(rel)

            if result.folders:
                for folder_path in result.folders:
                    stripped = folder_path.rstrip("/")
                    rel = (
                        posixpath.relpath(stripped, prefix.rstrip("/"))
                        if prefix
                        else stripped
                    )
                    if rel and rel != "." and "/" not in rel:
                        directories.append(rel)

            if not result.has_more:
                break
            cursor = result.cursor

        return sorted(directories), files

    def size(self, name):
        blob_path = self._get_blob_path(name)
        try:
            result = vblob.head(blob_path, token=self.token)
            return result.size
        except BlobNotFoundError:
            raise FileNotFoundError("File does not exist: %s" % name)

    def url(self, name):
        """Return the URL for *name*.

        For **public** blobs the URL is directly accessible in a browser.

        For **private** blobs the URL requires an
        ``Authorization: Bearer <token>`` request header and is therefore
        **not** suitable for embedding directly in HTML.  Serve private
        content through a Django view that proxies the download using the
        token stored in your application settings.

        .. note::
            Vercel Blob does not support presigned or time-limited URLs.
        """
        blob_path = self._get_blob_path(name)
        return self._build_url(blob_path)

    def get_available_name(self, name, max_length=None):
        """Return a path suitable for saving *name*.

        When :attr:`file_overwrite` is ``True`` (the default), the name is
        returned unchanged so that the existing blob is replaced.  Set
        ``VERCEL_BLOB_FILE_OVERWRITE = False`` to append a unique suffix
        instead.
        """
        name = clean_name(name)
        if self.file_overwrite:
            return get_available_overwrite_name(name, max_length)
        return super().get_available_name(name, max_length)
