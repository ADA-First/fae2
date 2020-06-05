"""
WSGI config for fae2 project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/
"""

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import traceback
import signal
import time

from django.core.wsgi import get_wsgi_application

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
# This is the setting recommended when running mod_wsgi in daemon mode (which we are)
os.environ['DJANGO_SETTINGS_MODULE'] = 'fae2.settings'
# This is the setting typically used
#os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fae2.settings")
# It took me so long to solve the `fae2.settings` ModuleNotFound` problems I was having
# that I am leaving both in place and just commenting out the one I don't need

try:
    application = get_wsgi_application()
    print('WSGI without exception')
except Exception:
    print('handling WSGI exception')
    # Error loading applications
    if 'mod_wsgi' in sys.modules:
        traceback.print_exc()
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(2.5)
