from setuptools import setup
import storages


def read(filename):
    with open(filename) as f:
        return f.read()


def get_requirements_tests():
    with open('requirements-tests.txt') as f:
        return f.readlines()

setup(
    name='django-storages',
    version=storages.__version__,
    packages=['storages', 'storages.backends'],
    author='Josh Schneier',
    author_email='josh.schneier@gmail.com',
    license='BSD',
    description='Support for many storages (S3, Libcloud, etc in Django.',
    long_description=read('README.rst') + '\n\n' + read('CHANGELOG.rst'),
    url='https://github.com/jschneier/django-storages',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.8',
        'Framework :: Django :: 1.9',
        'Framework :: Django :: 1.10',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    tests_require=get_requirements_tests(),
    test_suite='tests',
    zip_safe=False
)
