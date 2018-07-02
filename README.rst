===============
django-storages
===============


.. image:: https://img.shields.io/pypi/v/django-storages.svg
    :target: https://pypi.python.org/pypi/django-storages
    :alt: PyPI Version

.. image:: https://travis-ci.org/jschneier/django-storages.svg?branch=master
    :target: https://travis-ci.org/jschneier/django-storages
    :alt: Build Status

Installation
============
Installing from PyPI is as easy as doing:

.. code-block:: bash

  pip install django-storages

If you'd prefer to install from source (maybe there is a bugfix in master that
hasn't been released yet) then the magic incantation you are looking for is:

.. code-block:: bash

  pip install -e 'git+https://github.com/jschneier/django-storages.git#egg=django-storages'

Once that is done add ``storages`` to your ``INSTALLED_APPS`` and set ``DEFAULT_FILE_STORAGE`` to the
backend of your choice. If, for example, you want to use the boto3 backend you would set:

.. code-block:: python

  DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

There are also a number of settings available to control how each storage backend functions,
please consult the documentation for a comprehensive list.

About
=====
django-storages is a project to provide a variety of storage backends in a single library.

This library is usually compatible with the currently supported versions of
Django. Check the Trove classifiers in setup.py to be sure.

History
=======
This repo began as a fork of the original library under the package name of django-storages-redux and
became the official successor (releasing under django-storages on PyPI) in February of 2016.

Found a Bug? Something Unsupported?
===================================
I suspect that a few of the storage engines in backends/ have been unsupported
for quite a long time. I personally only really need the S3Storage backend but
welcome bug reports (and especially) patches and tests for some of the other
backends.

Issues are tracked via GitHub issues at the `project issue page
<https://github.com/jschneier/django-storages/issues>`_.

Documentation
=============
Documentation for django-storages is located at https://django-storages.readthedocs.org/.

Contributing
============

#. `Check for open issues
   <https://github.com/jschneier/django-storages/issues>`_ at the project
   issue page or open a new issue to start a discussion about a feature or bug.
#. Fork the `django-storages repository on GitHub
   <https://github.com/jschneier/django-storages>`_ to start making changes.
#. Add a test case to show that the bug is fixed or the feature is implemented
   correctly.
#. Bug me until I can merge your pull request. Also, don't forget to add
   yourself to ``AUTHORS``.
