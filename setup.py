from setuptools import setup

import storages

def read(filename):
    with open(filename) as f:
        return f.read()

setup(
    name='django-storages-redux',
    version=storages.__version__,
    packages=['storages', 'storages.backends'],
    author='Josh Schneier',
    author_email='josh.schneier@gmail.com',
    license='BSD',
    description='Support for many storages (S3, MogileFS, etc) in Django.',
    long_description=read('README.rst') + '\n\n' + read('CHANGELOG.rst'),
    url='https://github.com/jschneier/django-storages-redux',
    classifiers=[
        'Framework :: Django',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    tests_require=[
        'Django>=1.5',
        'pytest',
        'mock',
        'boto>=2.32.0'
    ],
    test_suite='tests',
    zip_safe=False
)
