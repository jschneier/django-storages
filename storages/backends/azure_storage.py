import sys
import warnings

from storages.backends import azure

warnings.warn(
    "The storages.azure_storage module has been renamed to storages.azure. The "
    "old name is still available as an alias but will be removed in "
    "django-storages 2.0.",
    DeprecationWarning
)

sys.modules[__name__] = azure
