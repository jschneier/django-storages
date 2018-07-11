import posixpath

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_text


def setting(name, default=None):
    """
    Helper function to get a Django setting by name. If setting doesn't exists
    it will return a default.

    :param name: Name of setting
    :type name: str
    :param default: Value if setting is unfound
    :returns: Setting's value
    """
    return getattr(settings, name, default)


def clean_name(name):
    """
    Cleans the name so that Windows style paths work
    """
    # Normalize Windows style paths
    clean_name = posixpath.normpath(name).replace('\\', '/')

    # os.path.normpath() can strip trailing slashes so we implement
    # a workaround here.
    if name.endswith('/') and not clean_name.endswith('/'):
        # Add a trailing slash as it was stripped.
        clean_name = clean_name + '/'

    # Given an empty string, os.path.normpath() will return ., which we don't want
    if clean_name == '.':
        clean_name = ''

    return clean_name


def safe_join(base, *paths):
    """
    A version of django.utils._os.safe_join for S3 paths.

    Joins one or more path components to the base path component
    intelligently. Returns a normalized version of the final path.

    The final path must be located inside of the base path component
    (otherwise a ValueError is raised).

    Paths outside the base path indicate a possible security
    sensitive operation.
    """
    base_path = force_text(base)
    base_path = base_path.rstrip('/')
    paths = [force_text(p) for p in paths]

    final_path = base_path + '/'
    for path in paths:
        _final_path = posixpath.normpath(posixpath.join(final_path, path))
        # posixpath.normpath() strips the trailing /. Add it back.
        if path.endswith('/') or _final_path + '/' == final_path:
            _final_path += '/'
        final_path = _final_path
    if final_path == base_path:
        final_path += '/'

    # Ensure final_path starts with base_path and that the next character after
    # the base path is /.
    base_path_len = len(base_path)
    if (not final_path.startswith(base_path) or final_path[base_path_len] != '/'):
        raise ValueError('the joined path is located outside of the base path'
                         ' component')

    return final_path.lstrip('/')


def check_location(storage):
    if storage.location.startswith('/'):
        correct = storage.location.lstrip('/')
        raise ImproperlyConfigured(
            "%s.location cannot begin with a leading slash. Found '%s'. Use '%s' instead." % (
                storage.__class__.__name__,
                storage.location,
                correct,
            )
        )
