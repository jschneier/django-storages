Digital Ocean
=============

Example configuration for using the AWS backend with Digital Ocean Spaces. 

Usage
*****

You can use the models/storage backends/views/etc from the blog post below to create a test site (called mysite) to try this out. Testing locally using runserver works.

https://simpleisbetterthancomplex.com/tutorial/2017/08/01/how-to-setup-amazon-s3-in-a-django-project.html

See the folder "s3-example-public-and-private" from the GitHub repo for that blog post: https://github.com/sibtc/simple-s3-setup

To get the access key and secret key, follow the getting started guide from DigitalOcean: https://www.digitalocean.com/community/tutorials/managing-access-to-digitalocean-spaces#option-1-%E2%80%94-sharing-access-to-spaces-with-access-keys

Public Configuration
********************

Put these values in your main settings.py file or whichever "public" configuration system you use (e.g. secure key/value storage). 

Some of these values are built-in, some of them are used by the code linked to in "Usage" above.

+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| Name                          | Description                                                                  | Example value                                                      |
+===============================+==============================================================================+====================================================================+
| AWS\_STORAGE\_BUCKET\_NAME    | The name of the storage bucket.                                              | mysite                                                             |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_S3\_ENDPOINT\_URL        | The endpoint url excluding the bucket name.                                  | https://nyc3.digitaloceanspaces.com                                |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_S3\_OBJECT\_PARAMETERS   | Default params for objects.                                                  | { 'CacheControl': 'max-age=86400' }                                |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_LOCATION                 | The folder within the space to store files.                                  | mysite                                                             |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_S3\_SIGNATURE\_VERSION   | Signature version. DigitalOcean only support v2 for pre-signed urls.         | s3=s3v2 (Version 2), s3v4=s3v4 (Version 4)                         |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_STATIC\_LOCATION         | The folder within the space to store static files.                           | '%s/static' % AWS_LOCATION                                         |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| STATICFILES\_STORAGE          | The storage backend to use for static files.                                 | 'mysite.storage\_backends.StaticStorage'                           |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| STATIC\_URL                   | The base URL for generating URLs to static files included in rendered pages. | "https://%s/%s/" % (AWS\_S3\_ENDPOINT\_URL, AWS\_STATIC\_LOCATION) |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_PUBLIC\_MEDIA\_LOCATION  | The folder within the space to store public media files.                     | '%s/media/public' % AWS_LOCATION                                   |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| DEFAULT\_FILE\_STORAGE        | The storage backend to use for public media files.                           | 'mysite.storage\_backends.PublicMediaStorage'                      |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| AWS\_PRIVATE\_MEDIA\_LOCATION | The folder within the space to store private media files.                    | '%s/media/private' % AWS_LOCATION                                  |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+
| PRIVATE\_FILE\_STORAGE        | The storage backend to use for private media files.                          | 'mysite.storage_backends.PrivateMediaStorage'                      |
+-------------------------------+------------------------------------------------------------------------------+--------------------------------------------------------------------+

Private Configuration
*********************

Put these values in your private settings file or whichever "private" configuration system you use (e.g. secure key/value storage). 

**Don't push these settings to any Git repository or any other public site. Do not share them.**

+--------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Name                     | Description                                                                                                                                                                                                 |
+==========================+=============================================================================================================================================================================================================+
| AWS\_ACCESS\_KEY\_ID     | The access key for the storage API. Although this can be public, it's useful to store it with the secret key to force the server admin to think about / change it, at the same time as changing the secret. |
+--------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| AWS\_SECRET\_ACCESS\_KEY | The secret key for the storage API. Never reveal this to anyone :)                                                                                                                                          |
+--------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
