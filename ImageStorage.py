
import os
from PIL import ImageFile as PILImageFile
from django.core.files.storage import FileSystemStorage


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
        bare_basename = basename if '.' not in basename else basename[:basename.rindex('.')]
        basename = bare_basename + '.' + extension
        
        name = os.path.join(dirname, basename)
        return super(ImageStorage, self).save(name, content)
    
