import datetime

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from storages import utils


class SettingTest(TestCase):
    def test_get_setting(self):
        value = utils.setting('SECRET_KEY')
        self.assertEqual(settings.SECRET_KEY, value)

    def test_setting_unfound(self):
        self.assertIsNone(utils.setting('FOO'))
        self.assertEqual(utils.setting('FOO', 'bar'), 'bar')
        with self.assertRaises(ImproperlyConfigured):
            utils.setting('FOO', strict=True)


class CleanNameTests(TestCase):
    def test_clean_name(self):
        """
        Test the base case of clean_name
        """
        path = utils.clean_name("path/to/somewhere")
        self.assertEqual(path, "path/to/somewhere")

    def test_clean_name_normalize(self):
        """
        Test the normalization of clean_name
        """
        path = utils.clean_name("path/to/../somewhere")
        self.assertEqual(path, "path/somewhere")

    def test_clean_name_trailing_slash(self):
        """
        Test the clean_name when the path has a trailing slash
        """
        path = utils.clean_name("path/to/somewhere/")
        self.assertEqual(path, "path/to/somewhere/")

    def test_clean_name_windows(self):
        """
        Test the clean_name when the path has a trailing slash
        """
        path = utils.clean_name("path\\to\\somewhere")
        self.assertEqual(path, "path/to/somewhere")


class SafeJoinTest(TestCase):
    def test_normal(self):
        path = utils.safe_join("", "path/to/somewhere", "other", "path/to/somewhere")
        self.assertEqual(path, "path/to/somewhere/other/path/to/somewhere")

    def test_with_dot(self):
        path = utils.safe_join("", "path/./somewhere/../other", "..",
                               ".", "to/./somewhere")
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
        path = utils.safe_join('base_url', dt.isoformat())
        self.assertEqual(path, 'base_url/2017-05-19T14:45:37.123456')

    def test_join_empty_string(self):
        path = utils.safe_join('base_url', '')
        self.assertEqual(path, 'base_url/')

    def test_with_base_url_and_dot(self):
        path = utils.safe_join('base_url', '.')
        self.assertEqual(path, 'base_url/')

    def test_with_base_url_and_dot_and_path_and_slash(self):
        path = utils.safe_join('base_url', '.', 'path/to/', '.')
        self.assertEqual(path, 'base_url/path/to/')

    def test_join_nothing(self):
        path = utils.safe_join('')
        self.assertEqual(path, '')

    def test_with_base_url_join_nothing(self):
        path = utils.safe_join('base_url')
        self.assertEqual(path, 'base_url/')
