import abc
from collections.abc import Iterable
from datetime import datetime

from siotls import TLSError


class TLSServiceError(TLSError):
    pass

class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass


class CRLServiceError(TLSServiceError):
    pass

class CRLServiceErrorGroup(TLSServiceErrorGroup):
    pass

class CRLService(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def request(self, urls: Iterable[str]) -> tuple[str | None, bytes | None]:
        raise NotImplementedError  # pragma: no cover

    def get(self, urls: Iterable[str]) -> tuple[str | None, bytes | None]:  # noqa: ARG002
        return (None, None)  # pragma: no cover

    def save(self, url: str, crl: bytes, expiration: datetime) -> None:  # noqa: B027
        pass  # pragma: no cover

    def delete(self, url: str) -> None:  # noqa: B027
        pass  # pragma: no cover


class OCSPServiceError(TLSServiceError):
    pass

class OCSPServiceErrorGroup(TLSServiceErrorGroup):
    pass

class OCSPService(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def request(self, url: str, ocsp_req: bytes) -> bytes:
        raise NotImplementedError  # pragma: no cover

    def save(self, ocsp_req: bytes, ocsp_res: bytes, expiration: datetime):  # noqa: B027
        pass  # pragma: no cover

    def delete(self, ocsp_req: bytes):  # noqa: B027
        pass  # pragma: no cover
