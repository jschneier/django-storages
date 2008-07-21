"""
=================
Django S3 storage
=================

Initialization::

    >>> from django.core.files.remote import RemoteFile
    >>> from django.core.files.storage import default_storage
    >>> from django.core.cache import cache
    >>> from models import Storage

An object without a file has limited functionality::

    >>> obj1 = Storage()
    >>> obj1.normal
    <FieldFile: None>
    >>> obj1.normal.size
    Traceback (most recent call last):
    ...
    ValueError: The 'normal' attribute has no file associated with it.

Saving a file enables full functionality::

    >>> obj1.normal.save('django_test.txt', 'content')
    >>> obj1.normal
    <FieldFile: tests/django_test.txt>
    >>> obj1.normal.size
    7
    >>> obj1.normal.read()
    'content'

Save another file with the same name::

    >>> obj2 = Storage()
    >>> obj2.normal.save('django_test.txt', 'more content')
    >>> obj2.normal
    <FieldFile: tests/django_test_.txt>
    >>> obj2.normal.size
    12

Push the objects into the cache to make sure they pickle properly::

    >>> cache.set('obj1', obj1)
    >>> cache.set('obj2', obj2)
    >>> cache.get('obj2').normal
    <FieldFile: tests/django_test_.txt>

Deleting an object deletes the file it uses, if there are no other objects
still using that file::

    >>> obj2.delete()
    >>> obj2.normal.save('django_test.txt', 'more content')
    >>> obj2.normal
    <FieldFile: tests/django_test_.txt>

Default values allow an object to access a single file::

    >>> obj3 = Storage.objects.create()
    >>> obj3.default
    <FieldFile: tests/default.txt>
    >>> obj3.default.read()
    'default content'

But it shouldn't be deleted, even if there are no more objects using it::

    >>> obj3.delete()
    >>> obj3 = Storage()
    >>> obj3.default.read()
    'default content'

Clean up the temporary files::

    >>> obj1.normal.delete()
    >>> obj2.normal.delete()
    >>> obj3.default.delete()
"""