Rackspace CloudFiles
====================

Requirements
************

Mosso's Cloud Files python module http://www.mosso.com/cloudfiles.jsp

Usage
*****

Add the following to your project's settings.py file::

    CLOUDFILES_USERNAME = 'YourUsername'
    CLOUDFILES_API_KEY = 'YourAPIKey'
    CLOUDFILES_CONTAINER = 'ContainerName'
    DEFAULT_FILE_STORAGE = 'backends.mosso.CloudFilesStorage'

    # Optional - use SSL
    CLOUDFILES_SSL = True

Optionally, you can implement the following custom upload_to in your models.py file. This will upload the file using the file name only to Cloud Files (e.g. 'myfile.jpg'). If you supply a string (e.g. upload_to='some/path'), your file name will include the path (e.g. 'some/path/myfile.jpg')::

    from backends.mosso import cloudfiles_upload_to

    class SomeKlass(models.Model):
        some_field = models.ImageField(upload_to=cloudfiles_upload_to)

Alternatively, if you don't want to set the DEFAULT_FILE_STORAGE, you can do the following in your models::

    from backends.mosso import CloudFilesStorage, cloudfiles_upload_to

    cloudfiles_storage = CloudFilesStorage()

    class SomeKlass(models.Model):
        some_field = models.ImageField(storage=cloudfiles_storage,
                                       upload_to=cloudfiles_upload_to)
