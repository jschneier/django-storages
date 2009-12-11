
import os

from django.core.files.storage import FileSystemStorage
from django.core.exceptions import ImproperlyConfigured

try:
    from PIL import ImageFile as PILImageFile
except ImportError:
    raise ImproperlyConfigured, "Could not load PIL dependency.\
    \nSee http://www.pythonware.com/products/pil/"


class ImageStorage(FileSystemStorage):
    """
    A FileSystemStorage which normalizes extensions for images.
    
    Comes from http://www.djangosnippets.org/snippets/965/
    """
    
    def find_extension(self, format):
        """Normalizes PIL-returned format into a standard, lowercase extension."""
        format = format.lower()
        
        if format == 'jpeg':
            format = 'jpg'
        
        return format
    
    def save(self, name, content):
        dirname = os.path.dirname(name)
        basename = os.path.basename(name)
        
        # Use PIL to determine filetype
        
        p = PILImageFile.Parser()
        while 1:
            data = content.read(1024)
            if not data:
                break
            p.feed(data)
            if p.image:
                im = p.image
                break
        
        extension = self.find_extension(im.format)
        
        # Does the basename already have an extension? If so, replace it.
        # bare as in without extension
        bare_basename, _ = os.path.splitext(basename)
        basename = bare_basename + '.' + extension
        
        name = os.path.join(dirname, basename)
        return super(ImageStorage, self).save(name, content)
    
