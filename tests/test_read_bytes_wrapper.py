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

    def test_with_string_file_default_encoding(self):
        """Test the default encoding behavior"""
        content = 'Hello, world!'
        file_obj = io.StringIO(content)
        # Create a custom file-like object with encoding attribute
        class StringIOWithEncoding:
            def __init__(self, content, encoding):
                self.content = content
                self.encoding = encoding
                self.closed = False

            def read(self, *args, **kwargs):
                return self.content

            def close(self):
                self.closed = True

        # Test with a file that has a custom encoding
        custom_file = StringIOWithEncoding(content, 'latin1')
        wrapper = ReadBytesWrapper(custom_file)
        self.assertEqual(wrapper.read(), content.encode('latin1'))

    def test_with_string_file_no_encoding(self):
        """Test fallback to utf-8 when no encoding is specified"""
        content = 'Hello, world!'
        # Create a file-like object without encoding attribute
        class StringIOWithoutEncoding:
            def __init__(self, content):
                self.content = content
                self.closed = False

            def read(self, *args, **kwargs):
                return self.content

            def close(self):
                self.closed = True

        custom_file = StringIOWithoutEncoding(content)
        wrapper = ReadBytesWrapper(custom_file)
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
