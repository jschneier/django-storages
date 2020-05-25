from django.conf import settings as django_settings
from django.core.files import File
from django.utils.module_loading import import_string

from storages.base import BaseStorage


class MultiStorageHandler(BaseStorage):
    """
    This Storage class handles two storage backends at the same time

    When saving a new file, it is saved in both storages
    For every other request on existing files, it checks first which storage it is located in

    This class overrides all methods from the django storage except
    get_valid_name, get_available_name and generate_filename
    """

    _old_storage = None
    _new_storage = None

    def __init__(self, **kwargs):
        self._dict_config = getattr(django_settings, 'MULTI_STORAGE_CONFIG', {})
        self._dict_config.update(kwargs)

        self._old_storage = self._create_storage(self._dict_config['old_storage'])
        self._new_storage = self._create_storage(self._dict_config['new_storage'])

    def _create_storage(self, storage_config):
        return import_string(storage_config['class'])(**storage_config['config'])

    # Transfer files from the old storage to the new one
    def _transfer_file(self, name):
        if self._old_storage.exists(name) and not self._new_storage.exists(name):
            with self._old_storage.open(name, 'rb') as f:
                self._new_storage.save(name, f)
            return True
        return False

    def _execute_or_transfer(self, func, name):
        try:
            return func(name)
        except Exception as err:
            if self._transfer_file(name):
                return func(name)
            raise err

    def open(self, name, mode='rb'):
        self._transfer_file(name)
        return self._new_storage.open(name, mode)

    def save(self, name, content, max_length=None):
        # We want to be sure we save the file with the same name in both storages
        # No overwrite ! (S3Boto3 default configuration is to overwrite existing files)

        if name is None:
            name = content.name

        if not hasattr(content, 'chunks'):
            content = File(content, name)

        while self._new_storage.exists(name) or self._old_storage.exists(name):
            name = self.get_available_name(name, max_length=max_length)

        self._old_storage.save(name, content)
        return self._new_storage.save(name, content)

    def path(self, name):
        raise NotImplementedError("This backend doesn't support absolute paths.")

    def delete(self, name):
        # Delete in both Storages
        self._old_storage.delete(name)
        self._new_storage.delete(name)

    def exists(self, name):
        if self._new_storage.exists(name):
            return True
        return self._transfer_file(name)

    def listdir(self, path):
        return self._new_storage.listdir(path)

    def size(self, name):
        return self._execute_or_transfer(self._new_storage.size, name)

    def url(self, name):
        self._transfer_file(name)
        return self._new_storage.url(name)

    def get_accessed_time(self, name):
        return self._execute_or_transfer(self._new_storage.get_accessed_time, name)

    def get_created_time(self, name):
        return self._execute_or_transfer(self._new_storage.get_created_time, name)

    def get_modified_time(self, name):
        return self._execute_or_transfer(self._new_storage.get_modified_time, name)

    def modified_time(self, name):
        return self._execute_or_transfer(self._new_storage.modified_time, name)

    def accessed_time(self, name):
        return self._execute_or_transfer(self._new_storage.accessed_time, name)

    def created_time(self, name):
        return self._execute_or_transfer(self._new_storage.created_time, name)
