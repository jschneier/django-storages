"""Tests for the Vercel Blob storage backend.

All network I/O is mocked; no real API calls are made.
"""

from unittest import mock
from unittest.mock import MagicMock
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import SuspiciousOperation
from django.core.files.base import ContentFile
from django.test import TestCase
from django.test import override_settings

try:
    from vercel.blob.errors import BlobError
    from vercel.blob.errors import BlobNotFoundError
except ImportError:
    # If vercel-py is not installed the test module still parses.  Tests that
    # require the package will simply fail on import rather than on the import
    # guard below.
    BlobError = Exception  # type: ignore[assignment,misc]
    BlobNotFoundError = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# A synthetic token in the canonical format:
#   vercel_blob_rw_{storeId}_{hash}
FAKE_TOKEN = "vercel_blob_rw_testStoreId_abcdef1234567890"
FAKE_STORE_ID = "testStoreId"
BASE_URL = f"https://{FAKE_STORE_ID}.public.blob.vercel-storage.com"
PRIVATE_BASE_URL = f"https://{FAKE_STORE_ID}.private.blob.vercel-storage.com"


def make_storage(**kwargs):
    """Create a :class:`VercelBlobStorage` with sane defaults for testing."""
    from storages.backends.vercel_blob import VercelBlobStorage

    kwargs.setdefault("token", FAKE_TOKEN)
    kwargs.setdefault("access", "public")
    return VercelBlobStorage(**kwargs)


def make_put_result(pathname="test.txt"):
    result = MagicMock()
    result.url = f"{BASE_URL}/{pathname}"
    result.download_url = f"{BASE_URL}/{pathname}?download=1"
    result.pathname = pathname
    result.content_type = "text/plain"
    result.content_disposition = f'attachment; filename="{pathname}"'
    return result


def make_head_result(pathname="test.txt", size=42, access="public"):
    base = BASE_URL if access == "public" else PRIVATE_BASE_URL
    result = MagicMock()
    result.size = size
    result.url = f"{base}/{pathname}"
    result.download_url = f"{base}/{pathname}?download=1"
    result.pathname = pathname
    result.content_type = "text/plain"
    result.content_disposition = f'attachment; filename="{pathname}"'
    result.cache_control = "public, max-age=31536000"
    return result


def make_get_result(pathname="test.txt", content=b"hello", access="public"):
    base = BASE_URL if access == "public" else PRIVATE_BASE_URL
    result = MagicMock()
    result.content = content
    result.size = len(content)
    result.url = f"{base}/{pathname}"
    result.download_url = f"{base}/{pathname}?download=1"
    result.pathname = pathname
    result.content_type = "text/plain"
    result.content_disposition = f'attachment; filename="{pathname}"'
    result.cache_control = "public, max-age=31536000"
    result.etag = '"abc123"'
    result.status_code = 200
    return result


def make_list_result(blobs=None, folders=None, has_more=False, cursor=None):
    result = MagicMock()
    result.blobs = blobs or []
    result.folders = folders
    result.has_more = has_more
    result.cursor = cursor
    return result


def make_blob_item(pathname):
    item = MagicMock()
    item.pathname = pathname
    return item


# ---------------------------------------------------------------------------
# Initialisation tests
# ---------------------------------------------------------------------------


class VercelBlobStorageInitTests(TestCase):
    def test_requires_token_empty_string(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with self.assertRaises(ImproperlyConfigured):
            VercelBlobStorage(token="")

    def test_requires_token_none(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with self.assertRaises(ImproperlyConfigured):
            VercelBlobStorage(token=None)

    def test_invalid_access_raises(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with self.assertRaises(ImproperlyConfigured):
            VercelBlobStorage(token=FAKE_TOKEN, access="read-only")

    def test_unknown_kwarg_raises(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with self.assertRaises(ImproperlyConfigured):
            VercelBlobStorage(token=FAKE_TOKEN, unknown_kwarg="x")

    def test_default_settings(self):
        storage = make_storage()
        self.assertEqual(storage.token, FAKE_TOKEN)
        self.assertEqual(storage.access, "public")
        self.assertEqual(storage.location, "")
        self.assertTrue(storage.file_overwrite)
        self.assertEqual(storage.default_content_type, "application/octet-stream")
        self.assertEqual(storage.max_memory_size, 0)

    def test_private_access(self):
        storage = make_storage(access="private")
        self.assertEqual(storage.access, "private")

    def test_location_prefix(self):
        storage = make_storage(location="uploads")
        self.assertEqual(storage.location, "uploads")

    @override_settings(VERCEL_BLOB_TOKEN="settings_token")
    def test_token_from_django_settings(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        storage = VercelBlobStorage()
        self.assertEqual(storage.token, "settings_token")

    def test_token_from_blob_env_var(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with mock.patch.dict("os.environ", {"BLOB_READ_WRITE_TOKEN": "env_token"}):
            storage = VercelBlobStorage()
            self.assertEqual(storage.token, "env_token")

    def test_token_from_vercel_env_var(self):
        from storages.backends.vercel_blob import VercelBlobStorage

        with mock.patch.dict(
            "os.environ", {"VERCEL_BLOB_READ_WRITE_TOKEN": "vercel_env_token"}
        ):
            storage = VercelBlobStorage()
            self.assertEqual(storage.token, "vercel_env_token")

    @override_settings(VERCEL_BLOB_FILE_OVERWRITE=False)
    def test_overwrite_from_django_settings(self):
        storage = make_storage()
        self.assertFalse(storage.file_overwrite)


# ---------------------------------------------------------------------------
# _save / save tests
# ---------------------------------------------------------------------------


class VercelBlobStorageSaveTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_calls_put_with_correct_args(self, mock_put):
        mock_put.return_value = make_put_result("hello.txt")
        storage = make_storage()

        name = storage.save("hello.txt", ContentFile(b"hello world"))

        mock_put.assert_called_once()
        args, kwargs = mock_put.call_args
        self.assertEqual(args[0], "hello.txt")
        self.assertEqual(kwargs["access"], "public")
        self.assertEqual(kwargs["overwrite"], True)
        self.assertEqual(kwargs["token"], FAKE_TOKEN)
        self.assertEqual(name, "hello.txt")

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_with_location_prefix(self, mock_put):
        mock_put.return_value = make_put_result("media/hello.txt")
        storage = make_storage(location="media")

        storage.save("hello.txt", ContentFile(b"hello"))

        path_arg = mock_put.call_args[0][0]
        self.assertEqual(path_arg, "media/hello.txt")

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_guesses_content_type_from_name(self, mock_put):
        mock_put.return_value = make_put_result("image.png")
        storage = make_storage()

        storage.save("image.png", ContentFile(b"\x89PNG"))

        self.assertEqual(mock_put.call_args[1]["content_type"], "image/png")

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_uses_content_type_attribute(self, mock_put):
        mock_put.return_value = make_put_result("file.bin")
        storage = make_storage()

        content = ContentFile(b"data")
        content.content_type = "application/pdf"
        storage.save("file.bin", content)

        self.assertEqual(mock_put.call_args[1]["content_type"], "application/pdf")

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_private_access(self, mock_put):
        mock_put.return_value = make_put_result("secret.txt")
        storage = make_storage(access="private")

        storage.save("secret.txt", ContentFile(b"secret"))

        self.assertEqual(mock_put.call_args[1]["access"], "private")

    @patch("storages.backends.vercel_blob.vblob.head")
    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_overwrite_false(self, mock_put, mock_head):
        # head returns not-found so Django sees the name as available.
        mock_head.side_effect = BlobNotFoundError()
        mock_put.return_value = make_put_result("file.txt")
        storage = make_storage(file_overwrite=False)

        storage.save("file.txt", ContentFile(b"data"))

        self.assertEqual(mock_put.call_args[1]["overwrite"], False)

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_returns_cleaned_name(self, mock_put):
        mock_put.return_value = make_put_result("subdir/file.txt")
        storage = make_storage()

        name = storage.save("subdir/file.txt", ContentFile(b"data"))

        self.assertEqual(name, "subdir/file.txt")

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_uses_default_content_type_as_fallback(self, mock_put):
        mock_put.return_value = make_put_result("no_extension")
        storage = make_storage(default_content_type="application/octet-stream")

        storage.save("no_extension", ContentFile(b"data"))

        self.assertEqual(
            mock_put.call_args[1]["content_type"], "application/octet-stream"
        )

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_save_sdk_exception_propagates(self, mock_put):
        mock_put.side_effect = BlobError("API error")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.save("file.txt", ContentFile(b"data"))


# ---------------------------------------------------------------------------
# _open / read tests
# ---------------------------------------------------------------------------


class VercelBlobStorageOpenTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.head")
    @patch("storages.backends.vercel_blob.vblob.get")
    def test_open_read_returns_content(self, mock_get, mock_head):
        mock_head.return_value = make_head_result("hello.txt")
        mock_get.return_value = make_get_result("hello.txt", content=b"hello world")
        storage = make_storage()

        with storage.open("hello.txt") as f:
            content = f.read()

        self.assertEqual(content, b"hello world")
        mock_head.assert_called_once_with("hello.txt", token=FAKE_TOKEN)
        mock_get.assert_called_once()
        get_kwargs = mock_get.call_args[1]
        self.assertEqual(get_kwargs["access"], "public")
        self.assertEqual(get_kwargs["token"], FAKE_TOKEN)

    @patch("storages.backends.vercel_blob.vblob.head")
    @patch("storages.backends.vercel_blob.vblob.get")
    def test_open_read_partial(self, mock_get, mock_head):
        mock_head.return_value = make_head_result("hello.txt")
        mock_get.return_value = make_get_result("hello.txt", content=b"hello world")
        storage = make_storage()

        with storage.open("hello.txt") as f:
            partial = f.read(5)

        self.assertEqual(partial, b"hello")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_open_nonexistent_raises_file_not_found(self, mock_head):
        mock_head.side_effect = BlobNotFoundError()
        storage = make_storage()

        with self.assertRaises(FileNotFoundError):
            storage.open("missing.txt")

    def test_open_write_mode_defers_network_call(self):
        """Opening in write mode must not make any network calls."""
        from storages.backends.vercel_blob import VercelBlobFile

        storage = make_storage()
        f = storage.open("newfile.txt", "wb")

        self.assertIsInstance(f, VercelBlobFile)
        self.assertIsNone(f._file)  # No fetch yet

    @patch("storages.backends.vercel_blob.vblob.put")
    def test_write_mode_flushes_on_close(self, mock_put):
        mock_put.return_value = make_put_result("newfile.txt")
        storage = make_storage()

        f = storage.open("newfile.txt", "wb")
        f.write(b"new content")
        f.close()

        mock_put.assert_called_once()
        args, _ = mock_put.call_args
        self.assertEqual(args[0], "newfile.txt")

    @patch("storages.backends.vercel_blob.vblob.head")
    @patch("storages.backends.vercel_blob.vblob.get")
    def test_open_private_blob(self, mock_get, mock_head):
        mock_head.return_value = make_head_result("secret.txt", access="private")
        mock_get.return_value = make_get_result(
            "secret.txt", content=b"secret data", access="private"
        )
        storage = make_storage(access="private")

        with storage.open("secret.txt") as f:
            content = f.read()

        self.assertEqual(content, b"secret data")
        get_kwargs = mock_get.call_args[1]
        self.assertEqual(get_kwargs["access"], "private")

    def test_read_mode_file_raises_on_write(self):
        from storages.backends.vercel_blob import VercelBlobFile

        storage = make_storage()
        f = VercelBlobFile("file.txt", "r", storage)
        f._file = MagicMock()

        with self.assertRaises(AttributeError):
            f.write(b"oops")

    def test_write_mode_file_raises_on_read(self):
        from storages.backends.vercel_blob import VercelBlobFile

        storage = make_storage()
        f = VercelBlobFile("file.txt", "w", storage)
        f._file = MagicMock()

        with self.assertRaises(AttributeError):
            f.read()

    def test_close_clean_file_no_upload(self):
        """Closing a write-mode file without writing must not call put()."""
        from storages.backends.vercel_blob import VercelBlobFile

        storage = make_storage()
        f = VercelBlobFile("file.txt", "w", storage)
        # Never wrote anything, so _file is still None.
        f.close()  # Must not raise or call the API.
        self.assertIsNone(f._file)


# ---------------------------------------------------------------------------
# delete tests
# ---------------------------------------------------------------------------


class VercelBlobStorageDeleteTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.delete")
    def test_delete_calls_sdk(self, mock_delete):
        storage = make_storage()
        storage.delete("hello.txt")

        mock_delete.assert_called_once_with("hello.txt", token=FAKE_TOKEN)

    @patch("storages.backends.vercel_blob.vblob.delete")
    def test_delete_with_location_prefix(self, mock_delete):
        storage = make_storage(location="uploads")
        storage.delete("file.txt")

        mock_delete.assert_called_once_with("uploads/file.txt", token=FAKE_TOKEN)

    @patch("storages.backends.vercel_blob.vblob.delete")
    def test_delete_nonexistent_does_not_raise(self, mock_delete):
        mock_delete.side_effect = BlobNotFoundError()
        storage = make_storage()

        # Must not raise.
        storage.delete("nonexistent.txt")

    @patch("storages.backends.vercel_blob.vblob.delete")
    def test_delete_sdk_error_propagates(self, mock_delete):
        mock_delete.side_effect = BlobError("store suspended")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.delete("file.txt")


# ---------------------------------------------------------------------------
# exists tests
# ---------------------------------------------------------------------------


class VercelBlobStorageExistsTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.head")
    def test_exists_true(self, mock_head):
        mock_head.return_value = make_head_result("hello.txt")
        storage = make_storage()

        self.assertTrue(storage.exists("hello.txt"))

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_exists_false(self, mock_head):
        mock_head.side_effect = BlobNotFoundError()
        storage = make_storage()

        self.assertFalse(storage.exists("missing.txt"))

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_exists_sdk_error_propagates(self, mock_head):
        mock_head.side_effect = BlobError("rate limited")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.exists("file.txt")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_exists_with_location(self, mock_head):
        mock_head.return_value = make_head_result("media/image.png")
        storage = make_storage(location="media")

        storage.exists("image.png")

        mock_head.assert_called_once_with("media/image.png", token=FAKE_TOKEN)


# ---------------------------------------------------------------------------
# url tests
# ---------------------------------------------------------------------------


class VercelBlobStorageURLTests(TestCase):
    def test_url_public(self):
        storage = make_storage()
        url = storage.url("hello.txt")
        self.assertEqual(url, f"{BASE_URL}/hello.txt")

    def test_url_private(self):
        storage = make_storage(access="private")
        url = storage.url("hello.txt")
        self.assertEqual(url, f"{PRIVATE_BASE_URL}/hello.txt")

    def test_url_with_location(self):
        storage = make_storage(location="media")
        url = storage.url("hello.txt")
        self.assertEqual(url, f"{BASE_URL}/media/hello.txt")

    def test_url_nested_path(self):
        storage = make_storage()
        url = storage.url("a/b/c.jpg")
        self.assertEqual(url, f"{BASE_URL}/a/b/c.jpg")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_url_fallback_to_head_when_store_id_missing(self, mock_head):
        """When the store ID cannot be parsed from the token, fall back to head()."""
        from storages.backends.vercel_blob import VercelBlobStorage

        canonical = "https://other.public.blob.vercel-storage.com/file.txt"
        head_result = MagicMock()
        head_result.url = canonical
        mock_head.return_value = head_result

        # Token without the expected number of underscore-delimited segments.
        storage = VercelBlobStorage(token="shorttoken")
        url = storage.url("file.txt")

        self.assertEqual(url, canonical)
        mock_head.assert_called_once()


# ---------------------------------------------------------------------------
# size tests
# ---------------------------------------------------------------------------


class VercelBlobStorageSizeTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.head")
    def test_size_returns_int(self, mock_head):
        mock_head.return_value = make_head_result("hello.txt", size=1024)
        storage = make_storage()

        self.assertEqual(storage.size("hello.txt"), 1024)

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_size_not_found_raises_file_not_found(self, mock_head):
        mock_head.side_effect = BlobNotFoundError()
        storage = make_storage()

        with self.assertRaises(FileNotFoundError):
            storage.size("missing.txt")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_size_with_location(self, mock_head):
        mock_head.return_value = make_head_result("media/img.jpg", size=512)
        storage = make_storage(location="media")

        storage.size("img.jpg")

        mock_head.assert_called_once_with("media/img.jpg", token=FAKE_TOKEN)


# ---------------------------------------------------------------------------
# listdir tests
# ---------------------------------------------------------------------------


class VercelBlobStorageListdirTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_returns_files_and_directories(self, mock_list):
        mock_list.return_value = make_list_result(
            blobs=[
                make_blob_item("media/doc.pdf"),
                make_blob_item("media/image.png"),
            ],
            folders=["media/images/"],
            has_more=False,
        )
        storage = make_storage()

        dirs, files = storage.listdir("media/")

        self.assertIn("images", dirs)
        self.assertIn("doc.pdf", files)
        self.assertIn("image.png", files)

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_excludes_nested_files(self, mock_list):
        mock_list.return_value = make_list_result(
            blobs=[
                make_blob_item("media/top.txt"),
                make_blob_item("media/images/nested.jpg"),
            ],
            has_more=False,
        )
        storage = make_storage()

        _, files = storage.listdir("media/")

        self.assertIn("top.txt", files)
        self.assertNotIn("nested.jpg", files)
        self.assertNotIn("images/nested.jpg", files)

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_pagination(self, mock_list):
        mock_list.side_effect = [
            make_list_result(
                blobs=[make_blob_item("media/a.txt")],
                has_more=True,
                cursor="next_page",
            ),
            make_list_result(
                blobs=[make_blob_item("media/b.txt")],
                has_more=False,
            ),
        ]
        storage = make_storage()

        _, files = storage.listdir("media/")

        self.assertEqual(mock_list.call_count, 2)
        second_call_kwargs = mock_list.call_args_list[1][1]
        self.assertEqual(second_call_kwargs["cursor"], "next_page")
        self.assertIn("a.txt", files)
        self.assertIn("b.txt", files)

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_directories_are_sorted(self, mock_list):
        mock_list.return_value = make_list_result(
            folders=["prefix/zoo/", "prefix/alpha/", "prefix/beta/"],
            has_more=False,
        )
        storage = make_storage()

        dirs, _ = storage.listdir("prefix/")

        self.assertEqual(dirs, sorted(dirs))

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_passes_token(self, mock_list):
        mock_list.return_value = make_list_result(has_more=False)
        storage = make_storage()

        storage.listdir("")

        mock_list.assert_called_once()
        self.assertEqual(mock_list.call_args[1]["token"], FAKE_TOKEN)

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_listdir_no_folders_key(self, mock_list):
        """If the API returns no folders key the result must not blow up."""
        mock_list.return_value = make_list_result(
            blobs=[make_blob_item("f.txt")],
            folders=None,
            has_more=False,
        )
        storage = make_storage()

        dirs, files = storage.listdir("")

        self.assertEqual(dirs, [])
        self.assertIn("f.txt", files)


# ---------------------------------------------------------------------------
# get_available_name / overwrite tests
# ---------------------------------------------------------------------------


class VercelBlobStorageOverwriteTests(TestCase):
    def test_overwrite_true_returns_same_name(self):
        storage = make_storage(file_overwrite=True)
        name = storage.get_available_name("existing.txt")
        self.assertEqual(name, "existing.txt")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_overwrite_false_appends_suffix_when_blob_exists(self, mock_head):
        # First call (original name) → exists; second call (suffixed name) → not found.
        mock_head.side_effect = [
            make_head_result("existing.txt"),
            BlobNotFoundError(),
        ]
        storage = make_storage(file_overwrite=False)

        name = storage.get_available_name("existing.txt")

        self.assertNotEqual(name, "existing.txt")
        self.assertIn("existing", name)

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_overwrite_false_returns_original_when_no_conflict(self, mock_head):
        mock_head.side_effect = BlobNotFoundError()
        storage = make_storage(file_overwrite=False)

        name = storage.get_available_name("new.txt")

        self.assertEqual(name, "new.txt")


# ---------------------------------------------------------------------------
# Security / path-traversal tests
# ---------------------------------------------------------------------------


class VercelBlobStorageSecurityTests(TestCase):
    def test_path_traversal_raises_suspicious_operation(self):
        storage = make_storage(location="media")
        with self.assertRaises(SuspiciousOperation):
            storage._get_blob_path("../../etc/passwd")


# ---------------------------------------------------------------------------
# SDK exception propagation tests
# ---------------------------------------------------------------------------


class VercelBlobStorageExceptionPropagationTests(TestCase):
    @patch("storages.backends.vercel_blob.vblob.put")
    def test_blob_error_on_save(self, mock_put):
        mock_put.side_effect = BlobError("Something went wrong")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.save("file.txt", ContentFile(b"data"))

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_blob_error_on_size(self, mock_head):
        mock_head.side_effect = BlobError("rate limited")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.size("file.txt")

    @patch("storages.backends.vercel_blob.vblob.head")
    def test_blob_error_on_open(self, mock_head):
        mock_head.side_effect = BlobError("store suspended")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.open("file.txt")

    @patch("storages.backends.vercel_blob.vblob.list_objects")
    def test_blob_error_on_listdir(self, mock_list):
        mock_list.side_effect = BlobError("rate limited")
        storage = make_storage()

        with self.assertRaises(BlobError):
            storage.listdir("")
