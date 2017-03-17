from __future__ import print_function

import mimetypes
import warnings

from django.conf import settings
from django.core.cache import cache
from django.utils.deconstruct import deconstructible
from django.utils.text import force_text
from django.http import HttpResponse, HttpResponseNotFound
from django.core.exceptions import ImproperlyConfigured
from django.core.files.storage import Storage

try:
    import mogilefs
except ImportError:
    raise ImproperlyConfigured("Could not load mogilefs dependency.\
    \nSee http://mogilefs.pbworks.com/Client-Libraries")

warnings.warn(
    'MogileFSStorage is unmaintained and will be removed in the next django-storages version'
    'See https://github.com/jschneier/django-storages/issues/202',
    PendingDeprecationWarning
)


@deconstructible
class MogileFSStorage(Storage):
    """MogileFS filesystem storage"""
    def __init__(self, base_url=settings.MEDIA_URL):

        # the MOGILEFS_MEDIA_URL overrides MEDIA_URL
        if hasattr(settings, 'MOGILEFS_MEDIA_URL'):
            self.base_url = settings.MOGILEFS_MEDIA_URL
        else:
            self.base_url = base_url

        for var in ('MOGILEFS_TRACKERS', 'MOGILEFS_DOMAIN',):
            if not hasattr(settings, var):
                raise ImproperlyConfigured("You must define %s to use the MogileFS backend." % var)

        self.trackers = settings.MOGILEFS_TRACKERS
        self.domain = settings.MOGILEFS_DOMAIN
        self.client = mogilefs.Client(self.domain, self.trackers)

    def get_mogile_paths(self, filename):
        return self.client.get_paths(filename)

    # The following methods define the Backend API

    def filesize(self, filename):
        raise NotImplemented
        #return os.path.getsize(self._get_absolute_path(filename))

    def path(self, filename):
        paths = self.get_mogile_paths(filename)
        if paths:
            return self.get_mogile_paths(filename)[0]
        else:
            return None

    def url(self, filename):
        return urlparse.urljoin(self.base_url, filename).replace('\\', '/')

    def open(self, filename, mode='rb'):
        raise NotImplemented
        #return open(self._get_absolute_path(filename), mode)

    def exists(self, filename):
        return filename in self.client

    def save(self, filename, raw_contents, max_length=None):
        filename = self.get_available_name(filename, max_length)

        if not hasattr(self, 'mogile_class'):
            self.mogile_class = None

        # Write the file to mogile
        success = self.client.send_file(filename, BytesIO(raw_contents), self.mogile_class)
        if success:
            print("Wrote file to key %s, %s@%s" % (filename, self.domain, self.trackers[0]))
        else:
            print("FAILURE writing file %s" % (filename))

        return force_text(filename.replace('\\', '/'))

    def delete(self, filename):
        self.client.delete(filename)


def serve_mogilefs_file(request, key=None):
    """
    Called when a user requests an image.
    Either reproxy the path to perlbal, or serve the image outright
    """
    # not the best way to do this, since we create a client each time
    mimetype = mimetypes.guess_type(key)[0] or "application/x-octet-stream"
    client = mogilefs.Client(settings.MOGILEFS_DOMAIN, settings.MOGILEFS_TRACKERS)
    if hasattr(settings, "SERVE_WITH_PERLBAL") and settings.SERVE_WITH_PERLBAL:
        # we're reproxying with perlbal

        # check the path cache

        path = cache.get(key)

        if not path:
            path = client.get_paths(key)
            cache.set(key, path, 60)

        if path:
            response = HttpResponse(content_type=mimetype)
            response['X-REPROXY-URL'] = path[0]
        else:
            response = HttpResponseNotFound()

    else:
        # we don't have perlbal, let's just serve the image via django
        file_data = client[key]
        if file_data:
            response = HttpResponse(file_data, mimetype=mimetype)
        else:
            response = HttpResponseNotFound()

    return response
