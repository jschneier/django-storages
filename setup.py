from setuptools import setup, find_packages
import storages

setup(
    name = 'django-storages-redux',
    version = storages.__version__,
    packages = find_packages(),

    author = 'Josh Schneier',
    author_email = 'josh.schneier@gmail.com',
    license = 'BSD',
    description = 'Support for many storages (S3, MogileFS, etc) in Django.',
    url='https://github.com/jschneier/django-storages-redux',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    test_suite='tests.main',
    zip_safe = False,
)
