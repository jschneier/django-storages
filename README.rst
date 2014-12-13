=====================
django-storages-redux
=====================

.. image:: https://travis-ci.org/jschneier/django-storages-redux.png?branch=master
        :target: https://travis-ci.org/jschneier/django-storages-redux


About
=====
django-storages was (is) a project to provide a variety of storage backends in
a single library. This is its maintained, Python 3 compatible fork. The reasons
for the fork are given in the next section.

At the moment the only tested Python 3 comptaible backend is the S3 Boto one
but some of them should work without issue (hashpath, symlink, overwrite).

This library maintains compatibility for all currently supported versions of
Django.

Why Fork?
=========
The BitBucket repo of the original django-storages has seen no commit applied
since March 2014 (it is currently December 2014) and no PyPi release since
March 2013 despite a wealth of bugfixes that were applied in that year-long
gap. There is plenty of community support for the django-storages project
(especially the S3BotoStorage piece) and I have a personal need for a Python3
compatible version.

All of the Python3 comptaible forks that currently exist (and there are a few)
are lacking in some way. This can be anything from the fact that they don't
release to PyPi, have no ongoing testing, didn't apply many important bugfixes
that have occurred on the bitbucket repo since forking or don't support older
versions of Python and Django (vital to finding bugs and keeping a large
community). For this fork I've done the small bit of work necessary to get a
tox + travis ci matrix going for all of the supported Python + Django versions.
In many cases the various forks are lacking in a few of the above ways.

Found a Bug? Something Unspported?
==================================
I suspect that a few of the storage engines in backends/ have been unspported
for quite a long time. I personally only really need the S3Storage backend but
welcome bug reports (and especially) patches and tests for some of the other
backends.

Issues are tracked via GitHub issues at the `project issue page
<https://github.com/jschneier/django-storages-redux/issues>`_.

Documentation
=============
The original documentation for django-storages is located at http://django-storages.readthedocs.org/.
Stay tuned for forthcoming documentation updates.


Contributing
============

#. `Check for open issues
   <https://github.com/jschneier/django-storages-redux/issues>`_ at the project
   issue page or open a new issue to start a discussion about a feature or bug.
#. Fork the `django-storages-redux repository on GitHub
   <https://github.com/jschneier/django-storages-redux>`_ to start making changes.
#. Add a test case to show that the bug is fixed or the feature is implemented
   correctly.
#. Bug me until I can merge your pull request. Also, don't forget to add
   yourself to ``AUTHORS``.

