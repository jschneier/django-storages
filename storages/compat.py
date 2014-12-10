from django.utils.six.moves.urllib import parse as urlparse
from django.utils.six import BytesIO

try:
    from django.utils.deconstruct import deconstructible
except ImportError: # Django 1.7+ migrations
    deconstructible = lambda klass, *args, **kwargs : klass
