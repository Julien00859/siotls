import importlib.metadata
import logging

__version__ = importlib.metadata.version(__name__)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

key_logger = logger.getChild('keylog')
key_logger.propagate = False
key_logger.setLevel(logging.DEBUG)
key_logger.addHandler(logging.NullHandler())

def __getattr__(attr):
    # using this trick so that __main__ is imported first
    if attr == 'TLSConnection':
        from .connection import TLSConnection
        return TLSConnection
    elif attr == 'TLSConfiguration':
        from .configuration import TLSConfiguration
        return TLSConfiguration
    raise AttributeError

# don't bloat dir(siotls) with useless stuff
del importlib.metadata
del logging
