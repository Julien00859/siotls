import sys
import logging
from siotls.__main__ import setup_logging

logging.basicConfig()
setup_logging(logging.DEBUG if '-vv' in sys.argv else logging.INFO)
