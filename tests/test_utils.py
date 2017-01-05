from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
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
