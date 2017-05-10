from __future__ import unicode_literals

import os
import sys
from optparse import make_option

from django.conf import settings
from django.utils.six.moves import input
from django.utils.encoding import smart_text
from django.utils.datastructures import SortedDict
from django.core.management.base import NoArgsCommand, CommandError
from django.core.files.storage import FileSystemStorage
from django.contrib.staticfiles.finders import BaseFinder, FileSystemFinder
from django.core.files import storage


class Command(NoArgsCommand):
    """
    Command that copies media files from settings.MEDIA_ROOT into the current
    settings.DEFAULT_FILE_STORAGE backend.
    """
    option_list = NoArgsCommand.option_list + (
        make_option('--noinput',
            action='store_false', dest='interactive', default=True,
            help="Do NOT prompt the user for input of any kind."),
        make_option('--no-post-process',
            action='store_false', dest='post_process', default=True,
            help="Do NOT post-process stored files."),
        make_option('-i', '--ignore', action='append', default=[],
            dest='ignore_patterns', metavar='PATTERN',
            help="Ignore files or directories matching this glob-style "
                "pattern. Use multiple times to ignore more."),
        make_option('-n', '--dry-run',
            action='store_true', dest='dry_run', default=False,
            help="Do everything except modify the filesystem."),
        make_option('-c', '--clear',
            action='store_true', dest='clear', default=False,
            help="Clear the existing files from the storage "
                 "before trying to copy the original files."),
        make_option('--no-default-ignore', action='store_false',
            dest='use_default_ignore_patterns', default=True,
            help="Don't ignore the common private glob-style patterns: 'CVS', "
                "'.*' and '*~'."),
    )
    help = 'Copies media files from MEDIA_ROOT into the currently configured DEFAULT_FILE_STORAGE.'
    requires_model_validation = False

    def __init__(self, *args, **kwargs):
        super(NoArgsCommand, self).__init__(*args, **kwargs)
        self.copied_files = []
        self.unmodified_files = []
        self.post_processed_files = []
        self.storage = storage.default_storage

    def set_options(self, **options):
        """
        Set instance variables based on the given options.
        """
        self.interactive = options['interactive']
        self.verbosity = int(options.get('verbosity', 1))
        self.clear = options['clear']
        self.dry_run = options['dry_run']
        ignore_patterns = options['ignore_patterns']
        if options['use_default_ignore_patterns']:
            ignore_patterns += ['CVS', '.*', '*~']
        self.ignore_patterns = list(set(ignore_patterns))
        self.post_process = options['post_process']

    def store(self):
        """
        Perform the bulk of store_media's work.

        This is split off from handle_noargs() to facilitate testing.
        """
        if self.clear:
            self.clear_dir('')

        found_files = SortedDict()
        finder = FileSystemMediaFinder()
        for path, storage in finder.list(self.ignore_patterns):
            # Prefix the relative path if the source storage specified it.
            # TODO: FileSystemStorage doesn't specify a prefix, so I think this block is useless.
            if getattr(storage, 'prefix', None):
                prefixed_path = os.path.join(storage.prefix, path)
            else:
                prefixed_path = path

            if prefixed_path not in found_files:
                found_files[prefixed_path] = (storage, path)
                self.copy_file(path, prefixed_path, storage)

        # Here we check if the storage backend has a post_process
        # method and pass it the list of modified files.
        if self.post_process and hasattr(self.storage, 'post_process'):
            processor = self.storage.post_process(found_files, dry_run=self.dry_run)
            for original_path, processed_path, processed in processor:
                if isinstance(processed, Exception):
                    self.stderr.write("Post-processing '{0}' failed!".format(original_path))
                    # Add a blank line before the traceback. Otherwise it's
                    # too easy to miss the relevant part of the error message.
                    self.stderr.write("")
                    raise processed
                if processed:
                    self.log("Post-processed '{0}' as '{1}'".format(original_path, processed_path), level=1)
                    self.post_processed_files.append(original_path)
                else:
                    self.log("Skipped post-processing '{0}'".format(original_path))

        return {
            'modified': self.copied_files,
            'unmodified': self.unmodified_files,
            'post_processed': self.post_processed_files,
        }

    def handle_noargs(self, **options):
        self.set_options(**options)

        message = ['\n']
        if self.dry_run:
            message.append('You have activated the --dry-run option, so no files will be modified.\n\n')

        message.append(
            'You have requested to copy media files from the MEDIA_ROOT folder\n'
            'into the {0} backend.\n\n'.format(settings.DEFAULT_FILE_STORAGE)
        )

        if self.clear:
            message.append(
                'This will DELETE ALL EXISTING FILES from the\n'
                '{0} backend!\n'
                'This includes any static files that have been collected into that backend!\n\n'.format(
                    settings.DEFAULT_FILE_STORAGE
                )
            )
        else:
            message.append(
                'This will overwrite existing files that are older than those\n'
                'in your MEDIA_ROOT folder!\n\n'
            )

        message.append(
            'Are you sure you want to do this?\n'
            "Type 'yes' to continue, or 'no' to cancel: "
        )

        if self.interactive and input(''.join(message)) != 'yes':
            raise CommandError("Storing media files cancelled.")

        stored = self.store()
        modified_count = len(stored['modified'])
        unmodified_count = len(stored['unmodified'])
        post_processed_count = len(stored['post_processed'])

        if self.verbosity >= 1:
            template = "\n{modified_count} {identifier} copied to {destination}{unmodified}{post_processed}.\n"
            summary = template.format(**{
                'modified_count': modified_count,
                'identifier': 'media file' + ('' if modified_count == 1 else 's'),
                'destination': settings.DEFAULT_FILE_STORAGE,
                'unmodified': (', {0} unmodified'.format(unmodified_count) if stored['unmodified'] else ''),
                'post_processed': (
                    ', {0} post-processed'.format(post_processed_count) if stored['post_processed'] else ''
                ),
            })
            self.stdout.write(summary)

    def log(self, msg, level=2):
        if self.verbosity >= level:
            self.stdout.write(msg)

    def clear_dir(self, path):
        """
        Deletes from the destination storage backend all files in the given relative path.
        """
        dirs, files = self.storage.listdir(path)
        for f in files:
            fpath = os.path.join(path, f)
            if self.dry_run:
                self.log("Pretending to delete '{0}'".format(smart_text(fpath), level=1))
            else:
                self.log("Deleting '{0}'".format(smart_text(fpath), level=1))
                self.storage.delete(fpath)
        for d in dirs:
            self.clear_dir(os.path.join(path, d))

    def delete_file(self, path, prefixed_path, source_storage):
        """
        Checks if the target file should be deleted if it already exists.
        If it shouldn't be deleted, the file is marked as unmodified.
        """
        if self.storage.exists(prefixed_path):
            try:
                # When was the target file last modified?
                target_last_modified = self.storage.modified_time(prefixed_path)
            except (OSError, NotImplementedError, AttributeError):
                # The storage doesn't support ``modified_time``, or otherwise failed.
                pass
            else:
                try:
                    # When was the source file last modified?
                    source_last_modified = source_storage.modified_time(path)
                except (OSError, NotImplementedError, AttributeError):
                    pass
                else:
                    # Do not delete the target file if it was modified more recently than the source.
                    # Avoid sub-second precision (see #14665, #19540).
                    if (target_last_modified.replace(microsecond=0)
                            >= source_last_modified.replace(microsecond=0)):
                        if prefixed_path not in self.unmodified_files:
                            self.unmodified_files.append(prefixed_path)
                        # Returning False here tells copy_file() to skip the file.
                        return False
            # The existing file is newer in MEDIA_ROOT than it is in the storage,
            # so delete the stored file so we can re-store it.
            if self.dry_run:
                self.log("Pretending to delete '{0}'".format(path))
            else:
                self.log("Deleting '{0}'".format(path))
                self.storage.delete(prefixed_path)
        return True

    def copy_file(self, path, prefixed_path, source_storage):
        """
        Attempt to copy ``path`` into the destination storage backend.
        """
        # Skip this file if it was already copied earlier.
        if prefixed_path in self.copied_files:
            return self.log("Skipping '{0}' (already copied earlier)".format(path))
        # Delete the target file if needed. Otherwise, skip the copy.
        if not self.delete_file(path, prefixed_path, source_storage):
            self.log("Skipping '{0}' (not modified)".format(path))
            return
        # The full path of the source file.
        source_path = source_storage.path(path)
        # Finally start copying.
        if self.dry_run:
            self.log("Pretending to copy '{0}'".format(source_path), level=1)
        else:
            self.log("Copying '{0}'".format(source_path), level=1)
            with source_storage.open(path) as source_file:
                self.storage.save(prefixed_path, source_file)
        if not prefixed_path in self.copied_files:
            self.copied_files.append(prefixed_path)


class FileSystemMediaFinder(FileSystemFinder):
    """
    A files finder that uses the ``MEDIA_ROOT`` setting to locate files.
    """
    def __init__(self, *args, **kwargs):
        # Maps dir paths to an appropriate storage instance
        self.storages = SortedDict()
        self.locations = [('', settings.MEDIA_ROOT)]
        self.storages[settings.MEDIA_ROOT] = FileSystemStorage(location=settings.MEDIA_ROOT)
