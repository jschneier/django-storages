import os
import django
from django.conf import settings

def pytest_configure():
    """Configure Django settings for testing."""
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            USE_TZ=True,
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sites",
                "storages",
            ],
            SITE_ID=1,
            MIDDLEWARE_CLASSES=(),
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
            # Storage-specific settings for tests
            LIBCLOUD_PROVIDERS={
                'default': {
                    'type': 'libcloud.storage.types.Provider.GOOGLE_STORAGE',
                    'user': 'test',
                    'key': 'test',
                    'bucket': 'test-bucket',
                }
            }
        )
        django.setup()
