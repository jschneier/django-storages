import io
import os
import sys
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import ReadBytesWrapper directly without Django dependencies
from storages.utils import ReadBytesWrapper

class TestReadBytesWrapperStandalone(unittest.TestCase):
    """Tests for ReadBytesWrapper that can run without Django settings"""

    def test_with_bytes_file(self):
        """Test with a file-like object that returns bytes"""
        content = b'Hello, world!'
        file_obj = io.BytesIO(content)
        wrapper = ReadBytesWrapper(file_obj)
        self.assertEqual(wrapper.read(), content)

    def test_with_string_file(self):
        """Test with a file-like object that returns strings"""
        content = 'Hello, world!'
        file_obj = io.StringIO(content)
        wrapper = ReadBytesWrapper(file_obj)
        self.assertEqual(wrapper.read(), content.encode('utf-8'))

    def test_with_string_file_specified_encoding(self):
        """Test with a specified encoding"""
        content = 'Hello, world!'
        file_obj = io.StringIO(content)
        wrapper = ReadBytesWrapper(file_obj, encoding='ascii')
        self.assertEqual(wrapper.read(), content.encode('ascii'))

    def test_with_string_file_detect_encoding(self):
        """Test that the wrapper uses the file's encoding if available"""
        content = 'Hello, world!'
        file_obj = io.StringIO(content)
        file_obj.encoding = 'latin1'
        wrapper = ReadBytesWrapper(file_obj)
        self.assertEqual(wrapper.read(), content.encode('latin1'))

    def test_with_string_file_fallback_encoding(self):
        """Test fallback to utf-8 when no encoding is specified"""
        content = 'Hello, world!'
        file_obj = io.StringIO(content)
        # Remove the encoding attribute if it exists
        if hasattr(file_obj, 'encoding'):
            delattr(file_obj, 'encoding')
        wrapper = ReadBytesWrapper(file_obj)
        self.assertEqual(wrapper.read(), content.encode('utf-8'))

    def test_close(self):
        """Test that close() is called on the wrapped file"""
        file_obj = io.BytesIO(b'Hello, world!')
        wrapper = ReadBytesWrapper(file_obj)
        wrapper.close()
        self.assertTrue(file_obj.closed)

    def test_readable(self):
        """Test that readable() returns True"""
        file_obj = io.BytesIO(b'Hello, world!')
        wrapper = ReadBytesWrapper(file_obj)
        self.assertTrue(wrapper.readable())

if __name__ == '__main__':
    unittest.main()
