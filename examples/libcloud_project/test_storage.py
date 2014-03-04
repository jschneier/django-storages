import sys, os
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_PATH)

from django.core.management import setup_environ
import settings
setup_environ(settings)

from storages.backends.apache_libcloud import LibCloudStorage

# test_google_storage is a key in settings LIBCLOUD_PROVIDERS dict
store = LibCloudStorage('test_google_storage')
# store is your django storage object that will use google storage
# bucket specified in configuration