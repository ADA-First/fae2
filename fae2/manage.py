#!/usr/bin/env python
from __future__ import absolute_import
import os
import sys

if __name__ == "__main__":
    os.environ['DJANGO_SETTINGS_MODULE'] = 'fae2.settings'

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
