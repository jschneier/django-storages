from setuptools import setup, find_packages
 
setup(
    name = 'django-storages',
    version = '1.1.1',
    packages = find_packages(),
    
    author = 'David Larlet',
    author_email = 'david@larlet.fr',
    license = 'BSD',
    description = 'Support for many storages (S3, MogileFS, etc) in Django.',
    url='http://code.welldev.org/django-storages/',
    download_url = "http://bitbucket.org/david/django-storages/get/1.1.1.tar.gz",
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
    ],
    py_modules = ['S3'],
    zip_safe = False,
)
