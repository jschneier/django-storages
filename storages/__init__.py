import warnings


class NewLibraryWarning(Warning):
    pass


warnings.simplefilter('always', category=NewLibraryWarning)
warnings.warn('This library has been designated as the official successor of django-storages and '
              'releases under that namespace. Please update your requirements files to point to '
              'django-storages.')

__version__ = '1.3.3'
