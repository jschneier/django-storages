from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import sys

import storages

# Some of this is based on drf and easy_thumbnails repos

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args['tests']
        self.test_suite = True

    def run_tests(self):
        import pytest
        sys.exit(pytest.main(self.test_args))

setup(
    name = 'django-storages-redux',
    version = storages.__version__,
    packages = find_packages(),

    author = 'Josh Schneier',
    author_email = 'josh.schneier@gmail.com',
    license = 'BSD',
    description = 'Support for many storages (S3, MogileFS, etc) in Django.',
    url='https://github.com/jschneier/django-storages-redux',
    cmd_class={'test': PyTest},
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    zip_safe=False
)
