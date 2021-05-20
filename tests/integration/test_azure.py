import io

from django import forms
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.template import Context, Template
from django.test import TestCase, override_settings
from django.utils import timezone

from storages.backends import azure_storage
from tests.integration.models import SimpleFileModel


class AzureStorageTest(TestCase):

    def setUp(self, *args):
        self.storage = azure_storage.AzureStorage()
        self.storage.is_emulated = True
        self.storage.account_name = "XXX"
        self.storage.account_key = "KXXX"
        self.storage.azure_container = "test"
        self.storage.service.delete_container(
            self.storage.azure_container, fail_not_exist=False)
        self.storage.service.create_container(
            self.storage.azure_container, public_access=False, fail_on_exist=False)

    def test_save(self):
        expected_name = "some blob Ϊ.txt"
        self.assertFalse(self.storage.exists(expected_name))
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save(expected_name, stream)
        self.assertEqual(name, expected_name)
        self.assertTrue(self.storage.exists(expected_name))

    def test_delete(self):
        self.storage.location = 'path'
        expected_name = "some blob Ϊ.txt"
        self.assertFalse(self.storage.exists(expected_name))
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save(expected_name, stream)
        self.assertEqual(name, expected_name)
        self.assertTrue(self.storage.exists(expected_name))
        self.storage.delete(expected_name)
        self.assertFalse(self.storage.exists(expected_name))

    def test_size(self):
        self.storage.location = 'path'
        expected_name = "some path/some blob Ϊ.txt"
        self.assertFalse(self.storage.exists(expected_name))
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save(expected_name, stream)
        self.assertEqual(name, expected_name)
        self.assertTrue(self.storage.exists(expected_name))
        self.assertEqual(self.storage.size(expected_name), len(b'Im a stream'))

    def test_url(self):
        self.assertTrue(
            self.storage.url("my_file.txt").endswith("/test/my_file.txt"))
        self.storage.expiration_secs = 360
        # has some query-string
        self.assertTrue("/test/my_file.txt?" in self.storage.url("my_file.txt"))

    def test_url_unsafe_chars(self):
        name = "my?file <foo>.txt"
        expected = "/test/my%3Ffile%20%3Cfoo%3E.txt"
        self.assertTrue(
            self.storage.url(name).endswith(expected))
        # has some query-string
        self.storage.expiration_secs = 360
        self.assertTrue("{}?".format(expected) in self.storage.url(name))

    def test_url_custom_endpoint(self):
        storage = azure_storage.AzureStorage()
        storage.is_emulated = True
        storage.custom_domain = 'foobar:123456'
        self.assertTrue(storage.url("my_file.txt").startswith('https://foobar:123456/'))

    @override_settings(USE_TZ=True)
    def test_get_modified_time_tz(self):
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('some path/some blob Ϊ.txt', stream)
        self.assertTrue(timezone.is_aware(self.storage.get_modified_time(name)))

    @override_settings(USE_TZ=False)
    def test_get_modified_time_no_tz(self):
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('some path/some blob Ϊ.txt', stream)
        self.assertTrue(timezone.is_naive(self.storage.get_modified_time(name)))

    @override_settings(USE_TZ=True)
    def test_modified_time_tz(self):
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('some path/some blob Ϊ.txt', stream)
        self.assertTrue(timezone.is_naive(self.storage.modified_time(name)))

    @override_settings(USE_TZ=False)
    def test_modified_time_no_tz(self):
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('some path/some blob Ϊ.txt', stream)
        self.assertTrue(timezone.is_naive(self.storage.modified_time(name)))

    def test_open_read(self):
        self.storage.location = 'root'
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('path/some file.txt', stream)
        fh = self.storage.open(name, 'r+b')
        try:
            self.assertEqual(fh.read(), b'Im a stream')
        finally:
            fh.close()

        stream = io.BytesIO()
        self.storage.service.get_blob_to_stream(
            container_name=self.storage.azure_container,
            blob_name='root/path/some file.txt',
            stream=stream,
            max_connections=1,
            timeout=10)
        stream.seek(0)
        self.assertEqual(stream.read(), b'Im a stream')

    def test_open_write(self):
        self.storage.location = 'root'
        name = 'file.txt'
        path = 'root/file.txt'
        fh = self.storage.open(name, 'wb')
        try:
            fh.write(b'foo')
        finally:
            fh.close()

        stream = io.BytesIO()
        self.storage.service.get_blob_to_stream(
            container_name=self.storage.azure_container,
            blob_name=path,
            stream=stream,
            max_connections=1,
            timeout=10)
        stream.seek(0)
        self.assertEqual(stream.read(), b'foo')

        # Write again

        fh = self.storage.open(name, 'wb')
        try:
            fh.write(b'bar')
        finally:
            fh.close()

        stream = io.BytesIO()
        self.storage.service.get_blob_to_stream(
            container_name=self.storage.azure_container,
            blob_name=path,
            stream=stream,
            max_connections=1,
            timeout=10)
        stream.seek(0)
        self.assertEqual(stream.read(), b'bar')

    def test_open_read_write(self):
        self.storage.location = 'root'
        stream = io.BytesIO(b'Im a stream')
        name = self.storage.save('file.txt', stream)
        fh = self.storage.open(name, 'r+b')
        try:
            self.assertEqual(fh.read(), b'Im a stream')
            fh.write(b' foo')
            fh.seek(0)
            self.assertEqual(fh.read(), b'Im a stream foo')
        finally:
            fh.close()

        stream = io.BytesIO()
        self.storage.service.get_blob_to_stream(
            container_name=self.storage.azure_container,
            blob_name='root/file.txt',
            stream=stream,
            max_connections=1,
            timeout=10)
        stream.seek(0)
        self.assertEqual(stream.read(), b'Im a stream foo')


class AzureStorageExpiry(azure_storage.AzureStorage):

    account_name = 'myaccount'
    account_key = 'mykey'
    azure_container = 'test_private'
    expiration_secs = 360


class AzureStorageSpecialChars(azure_storage.AzureStorage):
    def get_valid_name(self, name):
        return name


class FooFileForm(forms.Form):

    foo_file = forms.FileField()


class FooFileModelForm(forms.ModelForm):
    class Meta:
        model = SimpleFileModel
        fields = ['foo_file']


@override_settings(
    DEFAULT_FILE_STORAGE='storages.backends.azure_storage.AzureStorage',
    STATICFILES_STORAGE='storages.backends.azure_storage.AzureStorage')
class AzureStorageDjangoTest(TestCase):

    def setUp(self, *args):
        default_storage.service.delete_container(
            default_storage.azure_container, fail_not_exist=False)
        default_storage.service.create_container(
            default_storage.azure_container, public_access=False, fail_on_exist=False)

    def test_is_azure(self):
        self.assertIsInstance(default_storage, azure_storage.AzureStorage)

    def test_template_static_file(self):
        t = Template(
            '{% load static from staticfiles %}'
            '{% static "foo.txt" %}')
        self.assertEqual(
            t.render(Context({})).strip(),
            "https://127.0.0.1:10000/devstoreaccount1/test/foo.txt")

    @override_settings(
        DEFAULT_FILE_STORAGE='tests.integration.test_azure.AzureStorageExpiry')
    def test_template_media_file(self):
        t = Template('{{ file_url }}')
        rendered = t.render(Context({
            'file_url': default_storage.url('foo.txt')})).strip()
        self.assertTrue(
            "https://127.0.0.1:10000/devstoreaccount1/test_private/foo.txt?" in rendered)
        self.assertTrue("&amp;" in rendered)

        # check static files still work
        t = Template(
            '{% load static from staticfiles %}'
            '{% static "foo.txt" %}')
        self.assertEqual(
            t.render(Context({})).strip(),
            "https://127.0.0.1:10000/devstoreaccount1/test/foo.txt")

    def test_form(self):
        files = {
            'foo_file': SimpleUploadedFile(
                name='1234.pdf',
                content=b'foo content',
                content_type='application/pdf')}
        form = FooFileForm(data={}, files=files)
        self.assertTrue(form.is_valid())
        name = default_storage.save(
            'foo.pdf', form.cleaned_data['foo_file'])
        self.assertEqual(name, 'foo.pdf')
        self.assertTrue(default_storage.exists('foo.pdf'))

    def test_model_form(self):
        files = {
            'foo_file': SimpleUploadedFile(
                name='foo.pdf',
                content=b'foo content',
                content_type='application/pdf')}
        form = FooFileModelForm(data={}, files=files)
        self.assertTrue(form.is_valid())
        form.save()
        self.assertTrue(default_storage.exists('foo_uploads/foo.pdf'))

        # check file content was saved
        fh = default_storage.open('foo_uploads/foo.pdf', 'r+b')
        try:
            self.assertEqual(fh.read(), b'foo content')
        finally:
            fh.close()

    def test_name_clean_issue_609(self):
        """
        Should strip special characters when using the default storage
        """
        simple_file = SimpleFileModel()
        simple_file.foo_file = SimpleUploadedFile(
            name='foo%?:;~bar.txt',
            content=b'foo content')
        simple_file.save()
        self.assertEqual(simple_file.foo_file.name, 'foo_uploads/foobar.txt')
        self.assertTrue('foobar.txt' in simple_file.foo_file.url)

    @override_settings(
        DEFAULT_FILE_STORAGE='tests.integration.test_azure.AzureStorageSpecialChars')
    def test_name_clean_issue_609_with_special_chars(self):
        """
        Should not strip special chars
        """
        name = 'foo%?:;~bar.txt'
        simple_file = SimpleFileModel()
        simple_file.foo_file = SimpleUploadedFile(
            name=name,
            content=b'foo content')
        simple_file.save()
        self.assertEqual(
            simple_file.foo_file.name, 'foo_uploads/{}'.format(name))
        self.assertTrue(
            'foo_uploads/foo%25%3F%3A%3B~bar.txt' in simple_file.foo_file.url)
