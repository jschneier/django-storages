MogileFS
========

This storage allows you to use MogileFS, it comes from this blog post.

The MogileFS storage backend is fairly simple: it uses URLs (or, rather, parts of URLs) as keys into the mogile database. When the user requests a file stored by mogile (say, an avatar), the URL gets passed to a view which, using a client to the mogile tracker, retrieves the "correct" path (the path that points to the actual file data). The view will then either return the path(s) to perlbal to reproxy, or, if you're not using perlbal to reproxy (which you should), it serves the data of the file directly from django.

To use `MogileFSStorage` set::

    DEFAULT_FILE_STORAGE = 'storages.backends.mogile.MogileFSStorage'

The following settings are available:

``MOGILEFS_DOMAIN``
    The mogile domain that files should read from/written to, e.g "production"

``MOGILEFS_TRACKERS``
    A list of trackers to connect to, e.g. ["foo.sample.com:7001", "bar.sample.com:7001"]

``MOGILEFS_MEDIA_URL`` (optional)
    The prefix for URLs that point to mogile files. This is used in a similar way to ``MEDIA_URL``, e.g. "/mogilefs/"

``SERVE_WITH_PERLBAL``
    Boolean that, when True, will pass the paths back in the response in the ``X-REPROXY-URL`` header. If False, django will serve all mogile media files itself (bad idea for production, but useful if you're testing on a setup that doesn't have perlbal running)

Getting files into mogile
*************************

The great thing about file backends is that we just need to specify the backend in the model file and everything is taken care for us - all the default save() methods work correctly.

For Fluther, we have two main media types we use mogile for: avatars and thumbnails. Mogile defines "classes" that dictate how each type of file is replicated - so you can make sure you have 3 copies of the original avatar but only 1 of the thumbnail.

In order for classes to behave nicely with the backend framework, we've had to do a little tomfoolery. (This is something that may change in future versions of the filestorage framework).

Here's what the models.py file looks like for the avatars::

    from django.core.filestorage import storage

    # TODO: Find a better way to deal with classes. Maybe a generator?
    class AvatarStorage(storage.__class__):
        mogile_class = 'avatar'

    class ThumbnailStorage(storage.__class__):
        mogile_class = 'thumb'

    class Avatar(models.Model):
        user = models.ForeignKey(User, null=True, blank=True)
        image = models.ImageField(storage=AvatarStorage())
        thumb = models.ImageField(storage=ThumbnailStorage())

Each of the custom storage classes defines a class attribute which gets passed to the mogile backend behind the scenes. If you don't want to worry about mogile classes, don't need to define a custom storage engine or specify it in the field - the default should work just fine.

Serving files from mogile
*************************

Now, all we need to do is plug in the view that serves up mogile data.

Here's what we use::

    urlpatterns += patterns(",
        (r'^%s(?P<key>.*)' % settings.MOGILEFS_MEDIA_URL[1:],
            'MogileFSStorage.serve_mogilefs_file')
    )

Any url beginning with the value of ``MOGILEFS_MEDIA_URL`` will get passed to our view. Since ``MOGILEFS_MEDIA_URL`` requires a leading slash (like ``MEDIA_URL``), we strip that off and pass the rest of the url over to the view.

That's it! Happy mogiling!
