__version__ = __import__('importlib.metadata').metadata.version(__name__)

def __getattr__(attr):
    # using this trick so that __main__ is imported first
    if attr == 'TLSConnection':
        from .connection import TLSConnection
        return TLSConnection
    elif attr == 'TLSConfiguration':
        from .configuration import TLSConfiguration
        return TLSConfiguration
