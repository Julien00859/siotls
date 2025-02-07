from siotls import TLSError


class TLSServiceError(TLSError):
    pass


class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass


class TLSService:
    pass
