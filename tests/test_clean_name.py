import os
import sys
import pathlib
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storages.utils import clean_name

class CleanNameStandaloneTest(unittest.TestCase):
    """Tests for clean_name that can run without Django settings"""

    def test_empty_string(self):
        """Test that empty string remains empty"""
        self.assertEqual(clean_name(''), '')

    def test_dot(self):
        """Test that '.' becomes empty string"""
        self.assertEqual(clean_name('.'), '')

    def test_windows_path(self):
        """Test that Windows paths are normalized"""
        self.assertEqual(clean_name('foo\\bar'), 'foo/bar')

    def test_pathlib(self):
        """Test that pathlib.Path objects are handled correctly"""
        self.assertEqual(clean_name(pathlib.PurePath('foo/bar')), 'foo/bar')

    def test_pathlib_empty(self):
        """Test that empty pathlib.Path objects are handled correctly"""
        self.assertEqual(clean_name(pathlib.PurePath('')), '')

    def test_trailing_slash(self):
        """Test that trailing slashes are preserved"""
        self.assertEqual(clean_name('foo/bar/'), 'foo/bar/')

if __name__ == '__main__':
    unittest.main()
