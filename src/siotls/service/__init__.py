from siotls import TLSError

from .tls_service import TLSService


class TLSServiceError(TLSError):
    """
    Exception that services can raise to signal a resource couldn't be
    gathered, for the reason expressed in ``args[0]``. Signals siotls
    to retry with another service.
    """


class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass
