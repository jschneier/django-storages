from setuptools import setup

import storages


def read(filename):
    with open(filename) as f:
        return f.read()


setup(
    name='django-storages',
    version=storages.__version__,
    packages=['storages', 'storages.backends'],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires=['Django>=1.11'],
    extras_require={
        'azure': ['azure-storage-blob>=1.3.1,<12.0.0'],
        'boto': ['boto>=2.32.0'],
        'boto3': ['boto3>=1.4.4'],
        'dropbox': ['dropbox>=7.2.1'],
        'google': ['google-cloud-storage>=1.15.0'],
        'libcloud': ['apache-libcloud'],
        'sftp': ['paramiko'],
    },
    author='Josh Schneier',
    author_email='josh.schneier@gmail.com',
    license='BSD-3-Clause',
    description='Support for many storage backends in Django',
    long_description=read('README.rst') + '\n\n' + read('CHANGELOG.rst'),
    url='https://github.com/jschneier/django-storages',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Framework :: Django :: 3.0',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    test_suite='tests',
    zip_safe=False
)
