import importlib.metadata
import logging

__version__ = importlib.metadata.version(__name__)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

keylog = logger.getChild('keylog')
keylog.propagate = False
keylog.setLevel(logging.DEBUG)
keylog.addHandler(logging.NullHandler())

class TLSError(Exception):
    pass

from .configuration import TLSConfiguration
from .connection import TLSConnection

# don't bloat dir(siotls) with useless stuff
del importlib.metadata
del logging
