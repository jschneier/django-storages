#!/usr/bin/env python
"""
Configuration and launcher for storage tests.
"""
import os
import sys
import django
from django.conf import settings
from django.core.management import call_command

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(HERE)
sys.path[0:0] = [HERE, PARENT_DIR]

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEDIA_ROOT = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))
MEDIA_URL = '/media/'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'storages'
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)


settings.configure(
    ADMIN=('foo@bar'),
    MEDIA_ROOT=MEDIA_ROOT,
    MIDDLEWARE_CLASSES=(),
    INSTALLED_APPS=INSTALLED_APPS,
    DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    ROOT_URLCONF='testapp.urls',
    SECRET_KEY="it's a secret to everyone",
    SITE_ID=1,
    BASE_DIR=BASE_DIR,
    # Storages settings
    DEFAULT_FILE_STORAGE='backends.s3boto.S3BotoStorage',
    AWS_IS_GZIPPED=True,
    GS_IS_GZIPPED=True
)


def main():
    if django.VERSION >= (1, 7):
        django.setup()
    command_args = sys.argv[1:] or ['test', 'storages']
    call_command(*command_args)
    exit(0)

if __name__ == '__main__':
    main()
