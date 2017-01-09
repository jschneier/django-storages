from tempfile import SpooledTemporaryFile

from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import File
from django.utils.deconstruct import deconstructible
from django.utils.encoding import force_bytes, force_text, smart_str
from storages.compat import Storage
from storages.utils import clean_name, setting

try:
    from google.cloud.storage.client import Client
    from google.cloud.storage.blob import Blob
    from google.cloud.exceptions import NotFound
except ImportError:
    raise ImproperlyConfigured("Could not load Google Cloud Storage bindings.\n"
                               "See https://github.com/GoogleCloudPlatform/gcloud-python")


class GoogleCloudFile(File):
    def __init__(self, name, mode, storage, buffer_size=None):
        self.name = name
        self._mode = mode
        self._storage = storage
        self.blob = Blob(self.name, storage.bucket)
        self._file = None
        self._is_dirty = False

    @property
    def size(self):
        return self.blob.size

    def _get_file(self):
        if self._file is None:
            self._file = SpooledTemporaryFile(
                max_size=self._storage.max_memory_size,
                suffix=".GSStorageFile",
                dir=setting("FILE_UPLOAD_TEMP_DIR", None)
            )
            if 'r' in self._mode:
                self._is_dirty = False
                self.blob.download_to_file(self._file)
                self._file.seek(0)
        return self._file

    def _set_file(self, value):
        self._file = value

    file = property(_get_file, _set_file)

    def read(self, *args, **kwargs):
        if 'r' not in self._mode:
            raise AttributeError("File was not opened in read mode.")
        return super(GoogleCloudFile, self).read(*args, **kwargs)

    def write(self, content, *args, **kwargs):
        if 'w' not in self._mode:
            raise AttributeError("File was not opened in write mode.")
        self._is_dirty = True
        return super(GoogleCloudFile, self).write(force_bytes(content), *args, **kwargs)

    def close(self):
        if self._file is not None:
            if self._is_dirty:
                self.file.seek(0)
                self.blob.upload_from_file(self.file)
            self._file.close()
            self._file = None


@deconstructible
class GoogleCloudStorage(Storage):
    client_class = Client
    file_class = GoogleCloudFile

    not_found_exception = NotFound

    project_id = setting('GS_PROJECT_ID', None)
    credentials = setting('GS_CREDENTIALS', None)
    bucket_name = setting('GS_BUCKET_NAME', None)
    auto_create_bucket = setting('GS_AUTO_CREATE_BUCKET', False)
    default_acl = setting('GS_DEFAULT_ACL', 'public-read')
    bucket_acl = setting('GS_BUCKET_ACL', default_acl)
    file_name_charset = setting('GS_FILE_NAME_CHARSET', 'utf-8')
    file_overwrite = setting('GS_FILE_OVERWRITE', True)
    # The max amount of memory a returned file can take up before being
    # rolled over into a temporary file on disk. Default is 0: Do not roll over.
    max_memory_size = setting('GS_MAX_MEMORY_SIZE', 0)

    def __init__(self, **settings):
        # check if some of the settings we've provided as class attributes
        # need to be overwritten with values passed in here
        for name, value in settings.items():
            if hasattr(self, name):
                setattr(self, name, value)

        self._bucket = None
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = self.client_class(
                project=self.project_id,
                credentials=self.credentials
            )
        return self._client

    @property
    def bucket(self):
        if self._bucket is None:
            self._bucket = self._get_or_create_bucket(self.bucket_name)
        return self._bucket

    def _get_or_create_bucket(self, name):
        """
        Retrieves a bucket if it exists, otherwise creates it.
        """
        try:
            return self.client.get_bucket(name)
        except self.not_found_exception:
            if self.auto_create_bucket:
                bucket = self.client.create_bucket(name)
                bucket.acl.all().grant(self.bucket_acl)
                bucket.acl.save()
                return bucket
            raise ImproperlyConfigured("Bucket %s does not exist. Buckets "
                                       "can be automatically created by "
                                       "setting GS_AUTO_CREATE_BUCKET to "
                                       "``True``." % name)

    def _clean_name(self, name):
        """
        Cleans the name so that Windows style paths work
        """
        return clean_name(name)

    def _encode_name(self, name):
        return smart_str(name, encoding=self.file_name_charset)

    def _decode_name(self, name):
        return force_text(name, encoding=self.file_name_charset)

    def _open(self, name, mode='rb'):
        name = self._clean_name(name)
        file_object = self.file_class(name, mode, self)
        if not file_object.blob:
            raise IOError('File does not exist: %s' % name)
        return file_object

    def _save(self, name, content):
        name = self._clean_name(name)
        size = getattr(content, 'size')

        content.name = name
        encoded_name = self._encode_name(name)
        file = self.file_class(encoded_name, 'rw', self)
        file.blob.upload_from_file(content, size=size)
        return name

    def delete(self, name):
        name = self._clean_name(name)
        self.bucket.delete_blob(self._encode_name(name))

    def exists(self, name):
        if not name:  # root element aka the bucket
            try:
                self.bucket
                return True
            except ImproperlyConfigured:
                return False

        name = self._clean_name(name)
        return bool(self.bucket.get_blob(self._encode_name(name)))

    def listdir(self, name):
        name = self._clean_name(name)
        # for the bucket.list and logic below name needs to end in /
        # But for the root path "" we leave it as an empty string
        if name and not name.endswith('/'):
            name += '/'

        files_list = list(self.bucket.list_blobs(prefix=self._encode_name(name)))
        files = []
        dirs = set()

        base_parts = name.split("/")[:-1]
        for item in files_list:
            parts = item.name.split("/")
            parts = parts[len(base_parts):]
            if len(parts) == 1 and parts[0]:
                # File
                files.append(parts[0])
            elif len(parts) > 1 and parts[0]:
                # Directory
                dirs.add(parts[0])
        return list(dirs), files

    def size(self, name):
        name = self._encode_name(self._clean_name(name))
        blob = self.bucket.get_blob(self._encode_name(name))
        return blob.size if blob else 0

    def modified_time(self, name):
        name = self._clean_name(name)
        blob = self.bucket.get_blob(self._encode_name(name))
        return blob.updated if blob else None

    def url(self, name):
        # Preserve the trailing slash after normalizing the path.
        name = self._clean_name(name)
        blob = self.bucket.get_blob(self._encode_name(name))
        return blob.public_url if blob else None

    def get_available_name(self, name, max_length=None):
        if self.file_overwrite:
            name = self._clean_name(name)
            return name
        return super(GoogleCloudStorage, self).get_available_name(name, max_length)
