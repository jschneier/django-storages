from django.conf import settings


if settings.DEFAULT_FILE_STORAGE.endswith('mosso.CloudFilesStorage'):
    import warnings
    warnings.simplefilter('always', PendingDeprecationWarning)
    warnings.warn("The mosso module will be deprecated in version 1.2 of "
                  "django-storages. The CloudFiles code has been moved into"
                  "django-cumulus at http://github.com/richleland/django-cumulus.",
                  PendingDeprecationWarning)

