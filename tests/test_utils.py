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
