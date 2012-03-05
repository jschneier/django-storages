django-storages
===============

django-storages is a collection of custom storage backends for Django.

.. toctree::
   :maxdepth: 1
   :glob:

   backends/*

Installation
************

Use pip to install from PyPI::

    pip install django-storages

Add ``storages`` to your settings.py file::

    INSTALLED_APPS = (
        ...
        'storages',
        ...
    )

Each storage backend has its own unique settings you will need to add to your settings.py file. Read the documentation for your storage engine(s) of choice to determine what you need to add.

Contributing
************

To contribute to django-storages `create a fork`_ on bitbucket. Clone your fork, make some changes, and submit a pull request.

.. _create a fork: https://bitbucket.org/david/django-storages/fork

Issues
******

Use the bitbucket `issue tracker`_ for django-storages to submit bugs, issues, and feature requests.

.. _issue tracker: https://bitbucket.org/david/django-storages/issues

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

