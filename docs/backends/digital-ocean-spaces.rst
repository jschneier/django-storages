Digital Ocean Spaces
====================

Digital Ocean Spaces implements the S3 protocol so it's mostly compatible with `S3Boto3Storage`.

<<<<<<< HEAD
Usage
*****

This Backend is bases on `S3Boto3Storage` and provides settings in order to identify if a project is using S3 or Spaces.


First steps
-----------

To upload your media files to S3 set the following in your Django project settings file::

    DEFAULT_FILE_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesPublicMediaStorage'

To allow ``django-admin.py`` collectstatic to automatically put your static files in your bucket set the following in your settings.py::

    STATICFILES_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesStaticStorage'


Digital Ocean Spaces settings
------------------------------

The following are the settings you MUST set in your project settings file in order to get it working.

``DO_SPACES_ACCESS_KEY_ID``
    Your Digital Ocean Space id


``DO_SPACES_SECRET_ACCESS_KEY``
    Your Digital Ocean Space key

``DO_SPACES_SPACE_NAME``
    Your Digital Ocean Space name


``DO_SPACES_SPACE_FOLDER``
    The folder where the files will be created / readed.
    e.g: If you're creating a `blog` project you could set `blog` as your `DO_SPACES_SPACE_FOLDER`. This way you can make coexist different projects in the same Digital Ocean Space.


``DO_SPACES_ENDPOINT_URL``
    Your Digital Ocean Space endpoint url.
    eg: If your Digital Ocean Space is on `San francisco 2` you should set `https://sfo2.digitaloceanspaces.com` as your `DO_SPACES_ENDPOINT_URL`.


``DO_SPACES_CACHE_MAX_AGE``
  How much time(in seconds) your cache will be stored, default to 86400(24 hours).


``DO_SPACES_DEFAULT_ACL``
  The default Access Control List, e.g: 'public-read'


File location settings
----------------------

You can (optionally) set routes for STATIC & MEDIA files using the following settings

```
# Set File locations
DO_SPACES_STATIC_LOCATION = '{FOLDER}/static'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)
DO_SPACES_PUBLIC_MEDIA_LOCATION = '{FOLDER}/media/public'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)
DO_SPACES_PRIVATE_MEDIA_LOCATION = '{FOLDER}/media/private'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)

#  Static files config
STATIC_URL = 'https://{ENDPOINT_URL}/{STATIC_LOCATION}/'.format(
    ENDPOINT_URL=DO_SPACES_ENDPOINT_URL,
    STATIC_LOCATION=DO_SPACES_STATIC_LOCATION
)
```


Storage Backends settings
-------------------------

As seen on *First steps* now you can set `DEFAULT_FILE_STORAGE` and `STATICFILES_STORAGE` settings in order to set Digital Ocean Spaces as your project Storage Backend.

```
# Configure file storage settings
STATICFILES_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesStaticStorage'
DEFAULT_FILE_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesPublicMediaStorage'
PRIVATE_FILE_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesPrivateMediaStorage'
```

Full settings example
---------------------

```
DO_SPACES_ACCESS_KEY_ID = '<your_do_spaces_id>'
DO_SPACES_SECRET_ACCESS_KEY = '<your_do_spaces_secret_key>'
DO_SPACES_SPACE_NAME = '<your_do_spaces_name>'
DO_SPACES_SPACE_FOLDER = '<folder_to_save_files>'  # recommended: Your project name, e.g: 'blog'
DO_SPACES_ENDPOINT_URL = '<your_do_spaces_endpoint_url>'  # must be your Space endpoint url, e.g: 'https://sfo2.digitaloceanspaces.com'
DO_SPACES_CACHE_MAX_AGE = 86400
DO_SPACES_DEFAULT_ACL = None

# Set File locations
DO_SPACES_STATIC_LOCATION = '{FOLDER}/static'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)
DO_SPACES_PUBLIC_MEDIA_LOCATION = '{FOLDER}/media/public'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)
DO_SPACES_PRIVATE_MEDIA_LOCATION = '{FOLDER}/media/private'.format(
    FOLDER=DO_SPACES_SPACE_FOLDER
)

#  Static files config
STATIC_URL = 'https://{ENDPOINT_URL}/{STATIC_LOCATION}/'.format(
    ENDPOINT_URL=DO_SPACES_ENDPOINT_URL,
    STATIC_LOCATION=DO_SPACES_STATIC_LOCATION
)

# Configure file storage settings
STATICFILES_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesStaticStorage'
DEFAULT_FILE_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesPublicMediaStorage'
PRIVATE_FILE_STORAGE = 'storages.backends.do_spaces.DigitalOceanSpacesPrivateMediaStorage'
```

