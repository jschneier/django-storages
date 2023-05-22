import tempfile

import pytest
from django.core.exceptions import SuspiciousFileOperation
from django.core.files.base import ContentFile

from storages.backends import filesystem


@pytest.fixture()
def storage():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield filesystem.FileSystemOverwriteStorage(location=tmpdirname)


def test_save_overwrite(storage):
    content = ContentFile("content")
    name = "testfile.txt"
    storage.save(name, content)

    assert storage.exists(name)
    assert storage.size(name) == len(content)

    content2 = ContentFile("content2")
    storage.save(name, content2)
    # No rename was done; the same file was overwritten
    assert storage.exists(name)
    assert storage.size(name) == len(content2)


def test_filename_validate(storage):
    content = ContentFile("content")
    with pytest.raises(SuspiciousFileOperation):
        storage.save("/badfile.txt", content)

    with pytest.raises(SuspiciousFileOperation):
        storage.save("foo/../../../badfile.txt", content)
