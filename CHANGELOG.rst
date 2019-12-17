django-storages CHANGELOG
=========================

1.8 (2019-11-20)
****************

General
-------
- Add support for Django 3.0 (`#759`_)
- Update license identifier to unambiguous ``BSD-3-Clause``

S3
--

- Include error message raised when missing library is imported (`#776`_, `#793`_)

Google
------

- **Breaking** The minimum supported version of ``google-cloud-storage`` is now ``1.15.0`` which enables...
- Add setting ``GS_CUSTOM_ENDPOINT`` to allow usage of custom domains (`#775`_, `#648`_)

Azure
-----

- Fix extra installation by pinning version to < 12 (`#785`_)
- Add support for setting ``AZURE_CACHE_CONTROL`` header (`#780`_, `#674`_)

.. _#759: https://github.com/jschneier/django-storages/pull/759
.. _#776: https://github.com/jschneier/django-storages/issues/776
.. _#793: https://github.com/jschneier/django-storages/pull/793
.. _#775: https://github.com/jschneier/django-storages/issues/775
.. _#648: https://github.com/jschneier/django-storages/pull/648
.. _#785: https://github.com/jschneier/django-storages/pull/785
.. _#780: https://github.com/jschneier/django-storages/pull/780
.. _#674: https://github.com/jschneier/django-storages/issues/674


1.7.2 (2019-09-10)
******************

S3
--

- Avoid misleading ``AWS_DEFAULT_ACL`` warning for insecure ``default_acl`` when
  overridden as a class variable (`#591`_)
- Propagate file deletion to cache when ``preload_metadata`` is ``True``,
  (not the default) (`#743`_, `#749`_)
- Fix exception raised on closed file (common if using ``ManifestFilesMixin`` or
  ``collectstatic``. (`#382`_, `#754`_)

Azure
-----

- Pare down the required packages in ``extra_requires`` when installing the ``azure`` extra to only
  ``azure-storage-blob`` (`#680`_, `#684`_)
- Fix compatability with ``generate_blob_shared_access_signature`` updated signature (`#705`_, `#723`_)
- Fetching a file now uses the configured timeout rather than hardcoding one (`#727`_)
- Add support for configuring all blobservice options: ``AZURE_EMULATED_MODE``, ``AZURE_ENDPOINT_SUFFIX``,
  ``AZURE_CUSTOM_DOMAIN``, ``AZURE_CONNECTION_STRING``, ``AZURE_CUSTOM_CONNECTION_STRING``,
  ``AZURE_TOKEN_CREDENTIAL``. See the docs for more info. Huge thanks once again to @nitely. (`#750`_)
- Fix filename handling to not strip special characters (`#609`_, `#752`_)


Google Cloud
------------

- Set the file acl in the same call that uploads it (`#698`_)
- Reduce the number of queries and required permissions when ``GS_AUTO_CREATE_BUCKET`` is
  ``False`` (the default) (`#412`_, `#718`_)
- Set the ``predefined_acl`` when creating a ``GoogleCloudFile`` using ``.write``
  (`#640`_, `#756`_)
- Add ``GS_BLOB_CHUNK_SIZE`` setting to enable efficient uploading of large files (`#757`_)

Dropbox
-------

- Complete migration to v2 api with file fetching and metadata fixes (`#724`_)
- Add ``DROPBOX_TIMEOUT`` to configure client timeout defaulting to 100 seconds
  to match the underlying sdk. (`#419`_, `#747`_)

SFTP
----

- Fix reopening a file (`#746`_)

.. _#591: https://github.com/jschneier/django-storages/pull/591
.. _#680: https://github.com/jschneier/django-storages/issues/680
.. _#684: https://github.com/jschneier/django-storages/pull/684
.. _#698: https://github.com/jschneier/django-storages/pull/698
.. _#705: https://github.com/jschneier/django-storages/issues/705
.. _#723: https://github.com/jschneier/django-storages/pull/723
.. _#727: https://github.com/jschneier/django-storages/pull/727
.. _#746: https://github.com/jschneier/django-storages/pull/746
.. _#724: https://github.com/jschneier/django-storages/pull/724
.. _#412: https://github.com/jschneier/django-storages/pull/412
.. _#718: https://github.com/jschneier/django-storages/pull/718
.. _#743: https://github.com/jschneier/django-storages/issues/743
.. _#749: https://github.com/jschneier/django-storages/pull/749
.. _#750: https://github.com/jschneier/django-storages/pull/750
.. _#609: https://github.com/jschneier/django-storages/issues/609
.. _#752: https://github.com/jschneier/django-storages/pull/752
.. _#382: https://github.com/jschneier/django-storages/issues/382
.. _#754: https://github.com/jschneier/django-storages/pull/754
.. _#419: https://github.com/jschneier/django-storages/issues/419
.. _#747: https://github.com/jschneier/django-storages/pull/747
.. _#640: https://github.com/jschneier/django-storages/issues/640
.. _#756: https://github.com/jschneier/django-storages/pull/756
.. _#757: https://github.com/jschneier/django-storages/pull/757

1.7.1 (2018-09-06)
******************

- Fix off-by-1 error in ``get_available_name`` whenever ``file_overwrite`` or ``overwrite_files`` is ``True`` (`#588`_, `#589`_)
- Change ``S3Boto3Storage.listdir()`` to use ``list_objects`` instead of ``list_objects_v2`` to restore
  compatability with services implementing the S3 protocol that do not yet support the new method (`#586`_, `#590`_)

.. _#588: https://github.com/jschneier/django-storages/issues/588
.. _#589: https://github.com/jschneier/django-storages/pull/589
.. _#586: https://github.com/jschneier/django-storages/issues/586
.. _#590: https://github.com/jschneier/django-storages/pull/590

1.7 (2018-09-03)
****************

**Security**

- The ``S3BotoStorage`` and ``S3Boto3Storage`` backends have an insecure
  default ACL of ``public-read``. It is recommended that all current users audit their bucket
  permissions.  Support has been added for setting ``AWS_DEFAULT_ACL = None`` and ``AWS_BUCKET_ACL =
  None`` which causes all created files to inherit the bucket's ACL (and created buckets to inherit the
  Amazon account's default ACL). This will become the default in version 2.0 (for ``S3Boto3Storage`` only
  since ``S3BotoStorage`` will be removed in version 1.8, see below). Additionally, a warning is now
  raised if ``AWS_DEFAULT_ACL`` or ``AWS_BUCKET_ACL`` is not explicitly set. (`#381`_, `#535`_, `#579`_)

**Breaking**

- The ``AzureStorage`` backend and documentation has been completely rewritten. It now
  depends on ``azure`` and ``azure-storage-blob`` and is *vastly* improved. Big thanks to @nitely and all
  other contributors along the way (`#565`_)
- The ``.url()`` method of ``GoogleCloudStorage`` has been completely reworked. Many use
  cases should require no changes and will experience a massive speedup. The ``.url()`` method no longer hits
  the network for public urls and generates signed urls (with a default of 1-day expiration, configurable
  via ``GS_EXPIRATION``) for non-public buckets.  Check out the docs for more information. (`#570`_)
- Various backends will now raise ``ImproperlyConfigured`` at runtime if their
  location (``GS_LOCATION``, ``AWS_LOCATION``) begins with a leading ``/`` rather than silently
  stripping it.  Verify yours does not. (`#520`_)
- The long deprecated ``GSBotoStorage`` backend is removed. (`#518`_)

**Deprecation**

- The insecure default of ``public-read`` for ``AWS_DEFAULT_ACL`` and
  ``AWS_BUCKET_ACL`` in ``S3Boto3Storage`` will change to inherit the bucket's setting in version 2.0 (`#579`_)
- The legacy ``S3BotoBackend`` is deprecated and will be removed in version 1.8.
  It is strongly recommended to move to the ``S3Boto3Storage`` backend for performance,
  stability and bugfix reasons. See the `boto migration docs`_ for step-by-step guidelines. (`#578`_, `#584`_)
- The long aliased arguments to ``S3Boto3Storage`` of ``acl`` and ``bucket`` are
  deprecated in favor of ``bucket_name`` and ``default_acl`` (`#516`_)
- The minimum required version of ``boto3`` will be increasing to ``1.4.4`` in
  the next major version of ``django-storages``. (`#583`_)

**Features**

- Add support for a file to inherit its bucket's ACL by setting ``AWS_DEFAULT_ACL = None`` (`#535`_)
- Add ``GS_CACHE_CONTROL`` setting for ``GoogleCloudStorage`` backend (`#411`_, `#505`_)
- Add documentation around using django-storages with Digital Ocean Spaces (`#521`_)
- Add support for Django 2.1 and Python 3.7 (`#530`_)
- Make ``S3Boto3Storage`` pickleable (`#551`_)
- Add automatic reconnection to ``SFTPStorage`` (`#563`_, `#564`_)
- Unconditionally set the security token in the boto backends (`b13efd`_)
- Improve efficiency of ``.listdir`` on ``S3Boto3Storage`` (`#352`_)
- Add ``AWS_S3_VERIFY`` to support custom certificates and disabling certificate verification
  to ``S3Boto3Storage`` (`#486`_, `#580`_)
- Add ``AWS_S3_PROXIES`` setting to ``S3Boto3Storage`` (`#583`_)
- Add a snazzy new logo. Big thanks to @reallinfo

**Bugfixes**

- Reset file read offset before passing to ``GoogleCloudStorage`` and ``AzureStorage`` (`#481`_, `#581`_, `#582`_)
- Fix various issues with multipart uploads in the S3 backends
  (`#169`_, `#160`_, `#364`_, `#449`_, `#504`_, `#506`_, `#546`_)
- Fix ``S3Boto3Storage`` to stream down large files (also disallow `r+w` mode) (`#383`_, `#548`_)
- Fix ``SFTPStorageFile`` to align with the core ``File`` abstraction (`#487`_, `#568`_)
- Catch ``IOError`` in ``SFTPStorage.delete`` (`#568`_)
- ``AzureStorage``, ``GoogleCloudStorage``, ``S3Boto3Storage`` and ``S3BotoStorage`` now
  respect ``max_length`` when ``file_overwrite = True`` (`#513`_, `#554`_)
- The S3 backends now consistently use ``compresslevel=9`` (the Python stdlib default)
  for gzipped content (`#572`_, `#576`_)
- Improve error message of ``S3Boto3Storage`` during an unexpected exception when automatically
  creating a bucket (`#574`_, `#577`_)

.. _#381: https://github.com/jschneier/django-storages/issues/381
.. _#535: https://github.com/jschneier/django-storages/pull/535
.. _#579: https://github.com/jschneier/django-storages/pull/579
.. _#565: https://github.com/jschneier/django-storages/pull/565
.. _#520: https://github.com/jschneier/django-storages/pull/520
.. _#518: https://github.com/jschneier/django-storages/pull/518
.. _#516: https://github.com/jschneier/django-storages/pull/516
.. _#481: https://github.com/jschneier/django-storages/pull/481
.. _#581: https://github.com/jschneier/django-storages/pull/581
.. _#582: https://github.com/jschneier/django-storages/pull/582
.. _#411: https://github.com/jschneier/django-storages/issues/411
.. _#505: https://github.com/jschneier/django-storages/pull/505
.. _#521: https://github.com/jschneier/django-storages/pull/521
.. _#169: https://github.com/jschneier/django-storages/pull/169
.. _#160: https://github.com/jschneier/django-storages/issues/160
.. _#364: https://github.com/jschneier/django-storages/pull/364
.. _#449: https://github.com/jschneier/django-storages/issues/449
.. _#504: https://github.com/jschneier/django-storages/pull/504
.. _#530: https://github.com/jschneier/django-storages/pull/530
.. _#506: https://github.com/jschneier/django-storages/pull/506
.. _#546: https://github.com/jschneier/django-storages/pull/546
.. _#383: https://github.com/jschneier/django-storages/issues/383
.. _#548: https://github.com/jschneier/django-storages/pull/548
.. _b13efd: https://github.com/jschneier/django-storages/commit/b13efd92b3bf3e9967b8e7819224bfcf9abb977e
.. _#551: https://github.com/jschneier/django-storages/pull/551
.. _#563: https://github.com/jschneier/django-storages/issues/563
.. _#564: https://github.com/jschneier/django-storages/pull/564
.. _#487: https://github.com/jschneier/django-storages/issues/487
.. _#568: https://github.com/jschneier/django-storages/pull/568
.. _#513: https://github.com/jschneier/django-storages/issues/513
.. _#554: https://github.com/jschneier/django-storages/pull/554
.. _#570: https://github.com/jschneier/django-storages/pull/570
.. _#572: https://github.com/jschneier/django-storages/issues/572
.. _#576: https://github.com/jschneier/django-storages/pull/576
.. _#352: https://github.com/jschneier/django-storages/pull/352
.. _#574: https://github.com/jschneier/django-storages/issues/574
.. _#577: https://github.com/jschneier/django-storages/pull/577
.. _#486: https://github.com/jschneier/django-storages/pull/486
.. _#580: https://github.com/jschneier/django-storages/pull/580
.. _#583: https://github.com/jschneier/django-storages/pull/583
.. _boto migration docs:  https://django-storages.readthedocs.io/en/latest/backends/amazon-S3.html#migrating-boto-to-boto3
.. _#578: https://github.com/jschneier/django-storages/pull/578
.. _#584: https://github.com/jschneier/django-storages/pull/584

1.6.6 (2018-03-26)
******************

* You can now specify the backend you are using to install the necessary dependencies using
  ``extra_requires``. For example ``pip install django-storages[boto3]`` (`#417`_)
* Add additional content-type detection fallbacks (`#406`_, `#407`_)
* Add ``GS_LOCATION`` setting to specify subdirectory for ``GoogleCloudStorage`` (`#355`_)
* Add support for uploading large files to ``DropBoxStorage``, fix saving files (`#379`_, `#378`_, `#301`_)
* Drop support for Django 1.8 and Django 1.10 (and hence Python 3.3) (`#438`_)
* Implement ``get_created_time`` for ``GoogleCloudStorage`` (`#464`_)

.. _#417: https://github.com/jschneier/django-storages/pull/417
.. _#407: https://github.com/jschneier/django-storages/pull/407
.. _#406: https://github.com/jschneier/django-storages/issues/406
.. _#355: https://github.com/jschneier/django-storages/pull/355
.. _#379: https://github.com/jschneier/django-storages/pull/379
.. _#378: https://github.com/jschneier/django-storages/issues/378
.. _#301: https://github.com/jschneier/django-storages/issues/301
.. _#438: https://github.com/jschneier/django-storages/issues/438
.. _#464: https://github.com/jschneier/django-storages/pull/464

1.6.5 (2017-08-01)
******************

* Fix Django 1.11 regression with gzipped content being saved twice
  resulting in empty files (`#367`_, `#371`_, `#373`_)
* Fix the ``mtime`` when gzipping content on ``S3Boto3Storage`` (`#374`_)

.. _#367: https://github.com/jschneier/django-storages/issues/367
.. _#371: https://github.com/jschneier/django-storages/pull/371
.. _#373: https://github.com/jschneier/django-storages/pull/373
.. _#374: https://github.com/jschneier/django-storages/pull/374

1.6.4 (2017-07-27)
******************

* Files uploaded with ``GoogleCloudStorage`` will now set their appropriate mimetype (`#320`_)
* Fix ``DropBoxStorage.url`` to work. (`#357`_)
* Fix ``S3Boto3Storage`` when ``AWS_PRELOAD_METADATA = True`` (`#366`_)
* Fix ``S3Boto3Storage`` uploading file-like objects without names (`#195`_, `#368`_)
* ``S3Boto3Storage`` is now threadsafe - a separate session is created on a
  per-thread basis (`#268`_, `#358`_)

.. _#320: https://github.com/jschneier/django-storages/pull/320
.. _#357: https://github.com/jschneier/django-storages/pull/357
.. _#366: https://github.com/jschneier/django-storages/pull/366
.. _#195: https://github.com/jschneier/django-storages/pull/195
.. _#368: https://github.com/jschneier/django-storages/pull/368
.. _#268: https://github.com/jschneier/django-storages/issues/268
.. _#358: https://github.com/jschneier/django-storages/pull/358

1.6.3 (2017-06-23)
******************

* Revert default ``AWS_S3_SIGNATURE_VERSION`` to V2 to restore backwards
  compatability in ``S3Boto3``. It's recommended that all new projects set
  this to be ``'s3v4'``. (`#344`_)

.. _#344: https://github.com/jschneier/django-storages/pull/344

1.6.2 (2017-06-22)
******************

* Fix regression in ``safe_join()`` to handle a trailing slash in an
  intermediate path. (`#341`_)
* Fix regression in ``gs.GSBotoStorage`` getting an unexpected kwarg.
  (`#342`_)

.. _#341: https://github.com/jschneier/django-storages/pull/341
.. _#342: https://github.com/jschneier/django-storages/pull/342

1.6.1 (2017-06-22)
******************

* Drop support for Django 1.9 (`e89db45`_)
* Fix regression in ``safe_join()`` to allow joining a base path with an empty
  string. (`#336`_)

.. _e89db45: https://github.com/jschneier/django-storages/commit/e89db451d7e617638b5991e31df4c8de196546a6
.. _#336: https://github.com/jschneier/django-storages/pull/336

1.6 (2017-06-21)
******************

* **Breaking:** Remove backends deprecated in v1.5.1 (`#280`_)
* **Breaking:** ``DropBoxStorage`` has been upgrade to support v2 of the API, v1 will be shut off at the
  end of the month - upgrading is recommended (`#273`_)
* **Breaking:** The ``SFTPStorage`` backend now checks for the existence of the fallback ``~/.ssh/known_hosts``
  before attempting to load it.  If you had previously been passing in a path to a non-existent file it will no longer
  attempt to load the fallback. (`#118`_, `#325`_)
* **Breaking:** The default version value for ``AWS_S3_SIGNATURE_VERSION`` is now ``'s3v4'``. No changes should
  be required (`#335`_)
* **Deprecation:** The undocumented ``gs.GSBotoStorage`` backend. See the new ``gcloud.GoogleCloudStorage``
  or ``apache_libcloud.LibCloudStorage`` backends instead. (`#236`_)
* Add a new backend, ``gcloud.GoogleCloudStorage`` based on the ``google-cloud`` bindings. (`#236`_)
* Pass in the location constraint when auto creating a bucket in ``S3Boto3Storage`` (`#257`_, `#258`_)
* Add support for reading ``AWS_SESSION_TOKEN`` and ``AWS_SECURITY_TOKEN`` from the environment
  to ``S3Boto3Storage`` and ``S3BotoStorage``. (`#283`_)
* Fix Boto3 non-ascii filenames on Python 2.7 (`#216`_, `#217`_)
* Fix ``collectstatic`` timezone handling in and add ``get_modified_time`` to ``S3BotoStorage`` (`#290`_)
* Add support for Django 1.11 (`#295`_)
* Add ``project`` keyword support to GCS in ``LibCloudStorage`` backend (`#269`_)
* Files that have a guessable encoding (e.g. gzip or compress) will be uploaded with that Content-Encoding in
  the ``s3boto3`` backend (`#263`_, `#264`_)
* The Dropbox backend now properly translates backslashes in Windows paths into forward slashes (`e52a127`_)
* The S3 backends now permit colons in the keys (`#248`_, `#322`_)

.. _#217: https://github.com/jschneier/django-storages/pull/217
.. _#273: https://github.com/jschneier/django-storages/pull/273
.. _#216: https://github.com/jschneier/django-storages/issues/216
.. _#283: https://github.com/jschneier/django-storages/pull/283
.. _#280: https://github.com/jschneier/django-storages/pull/280
.. _#257: https://github.com/jschneier/django-storages/issues/257
.. _#258: https://github.com/jschneier/django-storages/pull/258
.. _#290: https://github.com/jschneier/django-storages/pull/290
.. _#295: https://github.com/jschneier/django-storages/pull/295
.. _#269: https://github.com/jschneier/django-storages/pull/269
.. _#263: https://github.com/jschneier/django-storages/issues/263
.. _#264: https://github.com/jschneier/django-storages/pull/264
.. _e52a127: https://github.com/jschneier/django-storages/commit/e52a127523fdd5be50bb670ccad566c5d527f3d1
.. _#236: https://github.com/jschneier/django-storages/pull/236
.. _#118: https://github.com/jschneier/django-storages/issues/118
.. _#325: https://github.com/jschneier/django-storages/pull/325
.. _#248: https://github.com/jschneier/django-storages/issues/248
.. _#322: https://github.com/jschneier/django-storages/pull/322
.. _#335: https://github.com/jschneier/django-storages/pull/335

1.5.2 (2017-01-13)
******************

* Actually use ``SFTP_STORAGE_HOST`` in ``SFTPStorage`` backend (`#204`_)
* Fix ``S3Boto3Storage`` to avoid race conditions in a multi-threaded WSGI environment (`#238`_)
* Fix trying to localize a naive datetime when ``settings.USE_TZ`` is ``False`` in ``S3Boto3Storage.modified_time``.
  (`#235`_, `#234`_)
* Fix automatic bucket creation in ``S3Boto3Storage`` when ``AWS_AUTO_CREATE_BUCKET`` is ``True`` (`#196`_)
* Improve the documentation for the S3 backends

.. _#204: https://github.com/jschneier/django-storages/pull/204
.. _#238: https://github.com/jschneier/django-storages/pull/238
.. _#234: https://github.com/jschneier/django-storages/issues/234
.. _#235: https://github.com/jschneier/django-storages/pull/235
.. _#196: https://github.com/jschneier/django-storages/pull/196

1.5.1 (2016-09-13)
******************

* **Breaking:** Drop support for Django 1.7 (`#185`_)
* **Deprecation:** hashpath, image, overwrite, mogile, symlinkorcopy, database, mogile, couchdb.
  See (`#202`_) to discuss maintenance going forward
* Use a fixed ``mtime`` argument for ``GzipFile`` in ``S3BotoStorage`` and ``S3Boto3Storage`` to ensure
  a stable output for gzipped files
* Use ``.putfileobj`` instead of ``.put`` in ``S3Boto3Storage`` to use the transfer manager,
  allowing files greater than 5GB to be put on S3 (`#194`_ , `#201`_)
* Update ``S3Boto3Storage`` for Django 1.10 (`#181`_) (``get_modified_time`` and ``get_accessed_time``)
* Fix bad kwarg name in ``S3Boto3Storage`` when `AWS_PRELOAD_METADATA` is `True` (`#189`_, `#190`_)

.. _#202: https://github.com/jschneier/django-storages/issues/202
.. _#201: https://github.com/jschneier/django-storages/pull/201
.. _#194: https://github.com/jschneier/django-storages/issues/194
.. _#190: https://github.com/jschneier/django-storages/pull/190
.. _#189: https://github.com/jschneier/django-storages/issues/189
.. _#185: https://github.com/jschneier/django-storages/pull/185
.. _#181: https://github.com/jschneier/django-storages/pull/181

1.5.0 (2016-08-02)
******************

* Add new backend ``S3Boto3Storage`` (`#179`_)
* Add a `strict` option to `utils.setting` (`#176`_)
* Tests, documentation, fixing ``.close`` for ``SFTPStorage`` (`#177`_)
* Tests, documentation, add `.readlines` for ``FTPStorage`` (`#175`_)
* Tests and documentation for ``DropBoxStorage`` (`#174`_)
* Fix ``MANIFEST.in`` to not ship ``.pyc`` files. (`#145`_)
* Enable CI testing of Python 3.5 and fix test failure from api change (`#171`_)

.. _#145: https://github.com/jschneier/django-storages/pull/145
.. _#171: https://github.com/jschneier/django-storages/pull/171
.. _#174: https://github.com/jschneier/django-storages/pull/174
.. _#175: https://github.com/jschneier/django-storages/pull/175
.. _#177: https://github.com/jschneier/django-storages/pull/177
.. _#176: https://github.com/jschneier/django-storages/pull/176
.. _#179: https://github.com/jschneier/django-storages/pull/179

1.4.1 (2016-04-07)
******************

* Files that have a guessable encoding (e.g. gzip or compress) will be uploaded with that Content-Encoding
  in the ``s3boto`` backend. Compressable types such as ``application/javascript`` will still be gzipped.
  PR `#122`_
* Fix ``DropBoxStorage.exists`` check and add ``DropBoxStorage.url`` (`#127`_)
* Add ``GS_HOST`` setting (with a default of ``GSConnection.DefaultHost``) to fix ``GSBotoStorage``.
  (`#124`_, `#125`_)

.. _#122: https://github.com/jschneier/django-storages/pull/122
.. _#127: https://github.com/jschneier/django-storages/pull/127
.. _#124: https://github.com/jschneier/django-storages/issues/124
.. _#125: https://github.com/jschneier/django-storages/pull/125

1.4 (2016-02-07)
****************

* This package is now released on PyPI as `django-storages`. Please update your requirements files to
  `django-storages==1.4`.

1.3.2 (2016-01-26)
******************

* Fix memory leak from not closing underlying temp file in ``s3boto`` backend (`#106`_)
* Allow easily specifying a custom expiry time when generating a url for ``S3BotoStorage`` (`#96`_)
* Check for bucket existence when the empty path ('') is passed to ``storage.exists`` in ``S3BotoStorage`` -
  this prevents a crash when running ``collectstatic -c`` on Django 1.9.1 (`#112`_) fixed in `#116`_

.. _#106: https://github.com/jschneier/django-storages/pull/106
.. _#96: https://github.com/jschneier/django-storages/pull/96
.. _#112: https://github.com/jschneier/django-storages/issues/112
.. _#116: https://github.com/jschneier/django-storages/pull/116


1.3.1 (2016-01-12)
******************

* A few Azure Storage fixes [pass the content-type to Azure, handle chunked content, fix ``url``] (`#45`__)
* Add support for a Dropbox (``dropbox``) storage backend
* Various fixes to the ``apache_libcloud`` backend [return the number of bytes asked for by ``.read``, make ``.name`` non-private, don't
  initialize to an empty ``BytesIO`` object] (`#55`_)
* Fix multi-part uploads in ``s3boto`` backend not respecting ``AWS_S3_ENCRYPTION`` (`#94`_)
* Automatically gzip svg files (`#100`_)

.. __: https://github.com/jschneier/django-storages/pull/45
.. _#76: https://github.com/jschneier/django-storages/pull/76
.. _#55: https://github.com/jschneier/django-storages/pull/55
.. _#94: https://github.com/jschneier/django-storages/pull/94
.. _#100: https://github.com/jschneier/django-storages/pull/100


1.3 (2015-08-14)
****************

* **Breaking:** Drop Support for Django 1.5 and Python 2.6
* **Breaking:** Remove previously deprecated mongodb backend
* **Breaking:** Remove previously deprecated ``parse_ts_extended`` from s3boto storage
* Add support for Django 1.8+ (`#36`__)
* Add ``AWS_S3_PROXY_HOST`` and ``AWS_S3_PROXY_PORT`` settings for s3boto backend (`#41`_)
* Fix Python3K compat issue in apache_libcloud (`#52`_)
* Fix Google Storage backend not respecting ``GS_IS_GZIPPED`` setting (`#51`__, `#60`_)
* Rename FTP ``_name`` attribute to ``name`` which is what the Django ``File`` api is expecting (`#70`_)
* Put ``StorageMixin`` first in inheritance to maintain backwards compat with older versions of Django (`#63`_)

.. __: https://github.com/jschneier/django-storages/pull/36
.. _#41: https://github.com/jschneier/django-storages/pull/41
.. _#52: https://github.com/jschneier/django-storages/issues/52
.. __: https://github.com/jschneier/django-storages/pull/51
.. _#60: https://github.com/jschneier/django-storages/pull/60
.. _#70: https://github.com/jschneier/django-storages/pull/70
.. _#63: https://github.com/jschneier/django-storages/pull/63


1.2.3 (2015-03-14)
******************

* Variety of FTP backend fixes (fix ``exists``, add ``modified_time``, remove call to non-existent function) (`#26`_)
* Apparently the year changed to 2015

.. _#26: https://github.com/jschneier/django-storages/pull/26


1.2.2 (2015-01-28)
******************

* Remove always show all warnings filter (`#21`_)
* Release package as a wheel
* Avoid resource warning during install (`#20`__)
* Made ``S3BotoStorage`` deconstructible (previously only ``S3BotoStorageFile`` was deconstructible) (`#19`_)

.. _#21: https://github.com/jschneier/django-storages/pull/21
.. __: https://github.com/jschneier/django-storages/issues/20
.. _#19: https://github.com/jschneier/django-storages/pull/19


1.2.1 (2014-12-31)
******************

* **Deprecation:** Issue warning about ``parse_ts_extended``
* **Deprecation:** mongodb backend - django-mongodb-engine now ships its own storage backend
* Fix ``storage.modified_time`` crashing on new files when ``AWS_PRELOAD_METADATA=True`` (`#11`_, `#12`__, `#14`_)

.. _#11: https://github.com/jschneier/django-storages/pull/11
__ https://github.com/jschneier/django-storages/issues/12
.. _#14: https://github.com/jschneier/django-storages/pull/14


1.2 (2014-12-14)
****************

* **Breaking:** Remove legacy S3 storage (`#1`_)
* **Breaking:** Remove mosso files backend (`#2`_)
* Add text/javascript mimetype to S3BotoStorage gzip allowed defaults
* Add support for Django 1.7 migrations in S3BotoStorage and ApacheLibCloudStorage (`#5`_, `#8`_)
* Python3K (3.3+) now available for S3Boto backend (`#4`_)

.. _#8: https://github.com/jschneier/django-storages/pull/8
.. _#5: https://github.com/jschneier/django-storages/pull/5
.. _#4: https://github.com/jschneier/django-storages/pull/4
.. _#1: https://github.com/jschneier/django-storages/issues/1
.. _#2: https://github.com/jschneier/django-storages/issues/2


**NOTE**: Version 1.1.9 is the first release of django-storages after the fork.
It represents the current (2014-12-08) state of the original django-storages in
master with no additional changes. This is the first release of the code base
since March 2013.

1.1.9 (2014-12-08)
******************

* Fix syntax for Python3 with pull-request `#91`_
* Support pushing content type from File object to GridFS with pull-request `#90`_
* Support passing a region to the libcloud driver with pull-request `#86`_
* Handle trailing slash paths fixes `#188`_ fixed by pull-request `#85`_
* Use a SpooledTemporaryFile to conserve memory in S3BotoFile pull-request `#69`_
* Guess content-type for S3BotoStorageFile the same way that _save() in S3BotoStorage does
* Pass headers and response_headers through from url to generate_url in S3BotoStorage pull-request `#65`_
* Added AWS_S3_HOST, AWS_S3_PORT and AWS_S3_USE_SSL settings to specify host, port and is_secure in pull-request `#66`_

.. _#91: https://bitbucket.org/david/django-storages/pull-request/91/
.. _#90: https://bitbucket.org/david/django-storages/pull-request/90/
.. _#86: https://bitbucket.org/david/django-storages/pull-request/86/
.. _#188: https://bitbucket.org/david/django-storages/issue/188/s3boto-_clean_name-is-broken-and-leads-to
.. _#85: https://bitbucket.org/david/django-storages/pull-request/85/
.. _#69: https://bitbucket.org/david/django-storages/pull-request/69/
.. _#66: https://bitbucket.org/david/django-storages/pull-request/66/
.. _#65: https://bitbucket.org/david/django-storages/pull-request/65/


**Everything Below Here Was Previously Released on PyPI under django-storages**


1.1.8 (2013-03-31)
******************

* Fixes `#156`_ regarding date parsing, ValueError when running collectstatic
* Proper handling of boto dev version parsing
* Made SFTP URLs accessible, now uses settings.MEDIA_URL instead of sftp://

.. _#156: https://bitbucket.org/david/django-storages/issue/156/s3boto-backend-valueerror-time-data-thu-07

1.1.7 (2013-03-20)
******************

* Listing of huge buckets on S3 is now prevented by using the prefix argument to boto's list() method
* Initial support for Windows Azure Storage
* Switched to useing boto's parse_ts date parser getting last modified info when using S3boto backend
* Fixed key handling in S3boto and Google Storage backends
* Account for lack of multipart upload in Google Storage backend
* Fixed seek() issue when using AWS_IS_GZIPPED by darkness51 with pull-request `#50`_
* Improvements to S3BotoStorage and GSBotoStorage

.. _#50: https://bitbucket.org/david/django-storages/pull-request/50/

1.1.6 (2013-01-06)
******************

* Merged many changes from Jannis Leidel (mostly regarding gzipping)
* Fixed tests by Ian Lewis
* Added support for Google Cloud Storage backend by Jannis Leidel
* Updated license file by Dan Loewenherz, fixes `#133`_ with pull-request `#44`_
* Set Content-Type header for use in upload_part_from_file by Gerardo Curiel
* Pass the rewind parameter to Boto's set_contents_from_file method by Jannis Leidel with pull-request `#45`_
* Fix for FTPStorageFile close() method by Mathieu Comandon with pull-request `#43`_
* Minor refactoring by Oktay Sancak with pull-request `#48`_
* Ungzip on download based on Content-Encoding by Gavin Wahl with pull-request `#46`_
* Add support for S3 server-side encryption by Tobias McNulty with pull-request `#17`_
* Add an optional setting to the boto storage to produce protocol-relative URLs, fixes `#105`_

.. _#133: https://bitbucket.org/david/django-storages/issue/133/license-file-refers-to-incorrect-project
.. _#44: https://bitbucket.org/david/django-storages/pull-request/44/
.. _#45: https://bitbucket.org/david/django-storages/pull-request/45/
.. _#43: https://bitbucket.org/david/django-storages/pull-request/43/
.. _#48: https://bitbucket.org/david/django-storages/pull-request/48/
.. _#46: https://bitbucket.org/david/django-storages/pull-request/46/
.. _#17: https://bitbucket.org/david/django-storages/pull-request/17/
.. _#105: https://bitbucket.org/david/django-storages/issue/105/add-option-to-produce-protocol-relative


1.1.5 (2012-07-18)
******************

* Merged pull request `#36`_ from freakboy3742 Keith-Magee, improvements to Apache Libcloud backend and docs
* Merged pull request `#35`_ from atodorov, allows more granular S3 access settings
* Add support for SSL in Rackspace Cloudfiles backend
* Fixed the listdir() method in s3boto backend, fixes `#57`_
* Added base url tests for safe_join in s3boto backend
* Merged pull request `#20`_ from alanjds, fixed SuspiciousOperation warning if AWS_LOCATION ends with '/'
* Added FILE_BUFFER_SIZE setting to s3boto backend
* Merged pull request `#30`_ from pendletongp, resolves `#108`_, `#109`_ and `#110`_
* Updated the modified_time() method so that it doesn't require dateutil. fixes `#111`_
* Merged pull request `#16`_ from chamal, adds Apache Libcloud backend
* When preloading the S3 metadata make sure we reset the files key during saving to prevent stale metadata
* Merged pull request `#24`_ from tobias.mcnulty, fixes bug where s3boto backend returns modified_time in wrong time zone
* Fixed HashPathStorage.location to no longer use settings.MEDIA_ROOT
* Remove download_url from setup file so PyPI dist is used

.. _#36: https://bitbucket.org/david/django-storages/pull-request/36/
.. _#35: https://bitbucket.org/david/django-storages/pull-request/35/
.. _#57: https://bitbucket.org/david/django-storages/issue/57
.. _#20: https://bitbucket.org/david/django-storages/pull-request/20/
.. _#30: https://bitbucket.org/david/django-storages/pull-request/30/
.. _#108: https://bitbucket.org/david/django-storages/issue/108
.. _#109: https://bitbucket.org/david/django-storages/issue/109
.. _#110: https://bitbucket.org/david/django-storages/issue/110
.. _#111: https://bitbucket.org/david/django-storages/issue/111
.. _#16: https://bitbucket.org/david/django-storages/pull-request/16/
.. _#24: https://bitbucket.org/david/django-storages/pull-request/24/

1.1.4 (2012-01-06)
******************

* Added PendingDeprecationWarning for mosso backend
* Merged pull request `#13`_ from marcoala, adds ``SFTP_KNOWN_HOST_FILE`` setting to SFTP storage backend
* Merged pull request `#12`_ from ryankask, fixes HashPathStorage tests that delete remote media
* Merged pull request `#10`_ from key, adds support for django-mongodb-engine 0.4.0 or later, fixes GridFS file deletion bug
* Fixed S3BotoStorage performance problem calling modified_time()
* Added deprecation warning for s3 backend, refs `#40`_
* Fixed CLOUDFILES_CONNECTION_KWARGS import error, fixes `#78`_
* Switched to sphinx documentation, set official docs up on https://django-storages.readthedocs.io/
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
