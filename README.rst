===============
django-storages
===============

.. image:: https://travis-ci.org/jschneier/django-storages.png?branch=master
    :target: https://travis-ci.org/jschneier/django-storages
    :alt: Build Status

.. image:: https://pypip.in/v/django-storages/badge.png
    :target: https://pypi.python.org/pypi/django-storages
    :alt: PyPI Version


Installation
============
Installing from PyPI is as easy as doing::

  pip install django-storages

If you'd prefer to install from source (maybe there is a bugfix in master that
hasn't been released yet) then the magic incantation you are looking for is::

  pip install -e 'git+https://github.com/jschneier/django-storages.git#egg=django-storages'

Once that is done add ``storages`` to your ``INSTALLED_APPS`` and set ``DEFAULT_FILE_STORAGE`` to the
backend of your choice. If, for example, you want to use the s3boto backend you would set::

  DEFAULT_FILE_STORAGE = 'storages.backends.s3boto.S3BotoStorage'

There are also a number of settings available to control how each storage backend functions,
please consult the documentation for a comprehensive list.

About
=====
django-storages is a project to provide a variety of storage backends in a single library.
This library is compatible with Django >= 1.7. It should also works with 1.6.2+ but no guarantees are made.

History
=======
This repo began as a fork of the original library under the package name of django-storages-redux and
became the official successor (releasing under django-storages on PyPI) in February of 2016. The initial
reasons for the fork are explained at the bottom of this document.

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
The original documentation for django-storages is located at http://django-storages.readthedocs.org/.
Stay tuned for forthcoming documentation updates.

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

Why Fork?
====================
The BitBucket repo of the original django-storages has seen no commit applied
since March 2014 (it is currently December 2014) and no PyPi release since
March 2013 despite a wealth of bugfixes that were applied in that year-long
gap. There is plenty of community support for the django-storages project
(especially the S3BotoStorage piece) and I have a personal need for a Python3
compatible version.

All of the Python3 compatible forks that currently exist (and there are a few)
are lacking in some way. This can be anything from the fact that they don't
release to PyPi, have no ongoing testing, didn't apply many important bugfixes
that have occurred on the Bitbucket repo since forking or don't support older
versions of Python and Django (vital to finding bugs and keeping a large
community). For this fork I've done the small bit of work necessary to get a
tox + travis ci matrix going for all of the supported Python + Django versions.
In many cases the various forks are lacking in a few of the above ways.
