from siotls import TLSError


class TLSServiceError(TLSError):
    pass


class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass


class TLSService:
    pass


class CRLService(TLSService):
    ...


class CRTService(TLSService):
    ...


class OCSPService(TLSService):
    ...
