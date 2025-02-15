import datetime
import io
import os.path
import pathlib

from django.conf import settings
from django.core.exceptions import SuspiciousFileOperation
from django.test import TestCase

from storages import utils
from storages.utils import get_available_overwrite_name as gaon


class SettingTest(TestCase):
    def test_get_setting(self):
        value = utils.setting("SECRET_KEY")
        self.assertEqual(settings.SECRET_KEY, value)


class CleanNameTests(TestCase):
    def test_clean_name(self):
        """Test the base case of clean_name."""
        path = utils.clean_name("path/to/somewhere")
        self.assertEqual(path, "path/to/somewhere")

    def test_clean_name_pathlib(self):
        """Test for pathlib.Path handling."""
        path = pathlib.Path("path/to/anywhere")
        self.assertEqual(utils.clean_name(path), "path/to/anywhere")

        path = pathlib.PurePath("path/to/anywhere")
        self.assertEqual(utils.clean_name(path), "path/to/anywhere")

    def test_clean_name_normalize(self):
        """
        Test the normalization of clean_name
        """
        path = utils.clean_name("path/to/../somewhere")
        self.assertEqual(path, "path/somewhere")

    def test_clean_name_trailing_slash(self):
        """Test the clean_name when the path has a trailing slash."""
        path = utils.clean_name("path/to/somewhere/")
        self.assertEqual(path, "path/to/somewhere/")

    def test_clean_name_windows(self):
        """Test the clean_name when the path has a trailing slash."""
        path = utils.clean_name("path\\to\\somewhere")
        self.assertEqual(path, "path/to/somewhere")


class SafeJoinTest(TestCase):
    def test_normal(self):
        path = utils.safe_join("", "path/to/somewhere", "other", "path/to/somewhere")
        self.assertEqual(path, "path/to/somewhere/other/path/to/somewhere")

    def test_with_dot(self):
        path = utils.safe_join(
            "", "path/./somewhere/../other", "..", ".", "to/./somewhere"
        )
        self.assertEqual(path, "path/to/somewhere")

    def test_with_only_dot(self):
        path = utils.safe_join("", ".")
        self.assertEqual(path, "")

    def test_base_url(self):
        path = utils.safe_join("base_url", "path/to/somewhere")
        self.assertEqual(path, "base_url/path/to/somewhere")

    def test_base_url_with_slash(self):
        path = utils.safe_join("base_url/", "path/to/somewhere")
        self.assertEqual(path, "base_url/path/to/somewhere")

    def test_suspicious_operation(self):
        with self.assertRaises(ValueError):
            utils.safe_join("base", "../../../../../../../etc/passwd")
        with self.assertRaises(ValueError):
            utils.safe_join("base", "/etc/passwd")

    def test_trailing_slash(self):
        """
        Test safe_join with paths that end with a trailing slash.
        """
        path = utils.safe_join("base_url/", "path/to/somewhere/")
        self.assertEqual(path, "base_url/path/to/somewhere/")

    def test_trailing_slash_multi(self):
        """
        Test safe_join with multiple paths that end with a trailing slash.
        """
        path = utils.safe_join("base_url/", "path/to/", "somewhere/")
        self.assertEqual(path, "base_url/path/to/somewhere/")

    def test_datetime_isoformat(self):
        dt = datetime.datetime(2017, 5, 19, 14, 45, 37, 123456)
        path = utils.safe_join("base_url", dt.isoformat())
        self.assertEqual(path, "base_url/2017-05-19T14:45:37.123456")

    def test_join_empty_string(self):
        path = utils.safe_join("base_url", "")
        self.assertEqual(path, "base_url/")

    def test_with_base_url_and_dot(self):
        path = utils.safe_join("base_url", ".")
        self.assertEqual(path, "base_url/")

    def test_with_base_url_and_dot_and_path_and_slash(self):
        path = utils.safe_join("base_url", ".", "path/to/", ".")
        self.assertEqual(path, "base_url/path/to/")

    def test_join_nothing(self):
        path = utils.safe_join("")
        self.assertEqual(path, "")

    def test_with_base_url_join_nothing(self):
        path = utils.safe_join("base_url")
        self.assertEqual(path, "base_url/")


class TestGetAvailableOverwriteName(TestCase):
    def test_maxlength_is_none(self):
        name = "superlong/file/with/path.txt"
        self.assertEqual(gaon(name, None), name)

    def test_maxlength_equals_name(self):
        name = "parent/child.txt"
        self.assertEqual(gaon(name, len(name)), name)

    def test_maxlength_is_greater_than_name(self):
        name = "parent/child.txt"
        self.assertEqual(gaon(name, len(name) + 1), name)

    def test_maxlength_less_than_name(self):
        name = "parent/child.txt"
        self.assertEqual(gaon(name, len(name) - 1), "parent/chil.txt")

    def test_truncates_away_filename_raises(self):
        name = "parent/child.txt"
        with self.assertRaises(SuspiciousFileOperation):
            gaon(name, len(name) - 5)

    def test_suspicious_file(self):
        name = "superlong/file/with/../path.txt"
        with self.assertRaises(SuspiciousFileOperation):
            gaon(name, 50)


class TestReadBytesWrapper(TestCase):
    def test_with_bytes_file(self):
        file = io.BytesIO(b"abcd")
        file_wrapped = utils.ReadBytesWrapper(file)

        # test read() with default args
        self.assertEqual(b"abcd", file_wrapped.read())

        # test seek() with default args
        self.assertEqual(0, file_wrapped.seek(0))
        self.assertEqual(b"abcd", file_wrapped.read())

        # test read() with custom args
        file_wrapped.seek(0)
        self.assertEqual(b"ab", file_wrapped.read(2))

        # test seek() with custom args
        self.assertEqual(1, file_wrapped.seek(-1, io.SEEK_CUR))
        self.assertEqual(b"bcd", file_wrapped.read())

    def test_with_string_file(self):
        file = io.StringIO("wxyz")
        file_wrapped = utils.ReadBytesWrapper(file)

        # test read() with default args
        self.assertEqual(b"wxyz", file_wrapped.read())

        # test seek() with default args
        self.assertEqual(0, file_wrapped.seek(0))
        self.assertEqual(b"wxyz", file_wrapped.read())

        # test read() with custom args
        file_wrapped.seek(0)
        self.assertEqual(b"wx", file_wrapped.read(2))

        # test seek() with custom args
        self.assertEqual(2, file_wrapped.seek(0, io.SEEK_CUR))
        self.assertEqual(b"yz", file_wrapped.read())

    # I chose the characters ™€‰ for the following tests because they produce different
    # bytes when encoding with utf-8 vs windows-1252 vs utf-16

    def test_with_string_file_specified_encoding(self):
        content = "\u2122\u20AC\u2030"
        file = io.StringIO(content)
        file_wrapped = utils.ReadBytesWrapper(file, encoding="utf-16")

        # test read() returns specified encoding
        self.assertEqual(file_wrapped.read(), content.encode("utf-16"))

    def test_with_string_file_detect_encoding(self):
        content = "\u2122\u20AC\u2030"
        with open(
            file=os.path.join(
                os.path.dirname(__file__), "test_files", "windows-1252-encoded.txt"
            ),
            mode="r",
            encoding="windows-1252",
        ) as file:
            self.assertEqual(file.read(), content)
            file.seek(0)

            file_wrapped = utils.ReadBytesWrapper(file)

            # test read() returns encoding detected from file object.
            self.assertEqual(file_wrapped.read(), content.encode("windows-1252"))

    def test_with_string_file_fallback_encoding(self):
        content = "\u2122\u20AC\u2030"
        file = io.StringIO(content)
        file_wrapped = utils.ReadBytesWrapper(file)

        # test read() returns fallback utf-8 encoding
        self.assertEqual(file_wrapped.read(), content.encode("utf-8"))
