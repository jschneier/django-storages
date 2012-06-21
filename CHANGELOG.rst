django-storages change log
==========================

1.1.4 (2012-01-06)
******************

* Added PendingDeprecationWarning for mosso backend
* Merged pull request `#13`_ from marcoala, adds ``SFTP_KNOWN_HOST_FILE`` setting to SFTP storage backend
* Merged pull request `#12`_ from ryankask, fixes HashPathStorage tests that delete remote media
* Merged pull request `#10`_ from key, adds support for django-mongodb-engine 0.4.0 or later, fixes GridFS file deletion bug
* Fixed S3BotoStorage performance problem calling modified_time()
* Added deprecation warning for s3 backend, refs `#40`_
* Fixed CLOUDFILES_CONNECTION_KWARGS import error, fixes `#78`_
* Switched to sphinx documentation, set official docs up on http://django-storages.rtfd.org/
* HashPathStorage uses self.exists now, fixes `#83`_

.. _#13: https://bitbucket.org/david/django-storages/pull-request/13/a-version-of-sftp-storage-that-allows-you
.. _#12: https://bitbucket.org/david/django-storages/pull-request/12/hashpathstorage-tests-deleted-my-projects
.. _#10: https://bitbucket.org/david/django-storages/pull-request/10/support-django-mongodb-engine-040
.. _#40: https://bitbucket.org/david/django-storages/issue/40/deprecate-s3py-backend
.. _#78: https://bitbucket.org/david/django-storages/issue/78/import-error
.. _#83: https://bitbucket.org/david/django-storages/issue/6/symlinkorcopystorage-new-custom-storage

1.1.3 (2011-08-15)
******************

* Created this lovely change log
* Fixed `#89`_: broken StringIO import in CloudFiles backend
* Merged `pull request #5`_: HashPathStorage path bug

.. _#89: https://bitbucket.org/david/django-storages/issue/89/112-broke-the-mosso-backend
.. _pull request #5: https://bitbucket.org/david/django-storages/pull-request/5/fixed-path-bug-and-added-testcase-for

