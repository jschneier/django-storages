#!/usr/bin/env python

# XXX we need manage.py until pytest-django is fixed
# https://github.com/pytest-dev/pytest-django/issues/639

import sys

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
