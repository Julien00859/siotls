import abc
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from pyasn1_modules.rfc5280 import Certificate, CertificateList
from pyasn1_modules.rfc6960 import BasicOCSPResponse

from siotls import TLSError
from siotls.service.ocsp import load_verify_ocsp
from siotls.x509.loader import (
    DerCertificate,
    DerCRL,
    DerOCSPRequest,
    DerOCSPResponse,
)

from .filestore import FileStore
from .sievecache import SieveCache


class TLSServiceError(TLSError):
    """
    Exception that services can raise to signal a resource couldn't be
    gathered, for the reason expressed in ``args[0]``. Signals siotls
    to retry with another service.
    """


class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass


class _CacheHelper:
    def __init__(self, cache, stale=timedelta(seconds=60)):
        self._cache = cache
        self.state = stale

    def get(self, key, default=None):
        data, expire = self._cache.get(key, (None, None))
        if not data:
            return default
        now = datetime.now(UTC)
        if now > expire - self.stale:
            self.rem(key)
            return default
        return data

    def set(self, key, data, expire):
        self._cache[key] = (data, expire)

    def rem(self, key):
        self._cache.pop(key)


class TLSService(metaclass=abc.ABCMeta):
    def __init__(self, *, ocsp_cache=None, file_cache=None):
        self._ocsp_cache = _CacheHelper(ocsp_cache or SieveCache())
        self._file_cache = _CacheHelper(file_cache or FileStore())

    def request_ocsp(
        self,
        url: bytes,
        ocsp_req_data: DerOCSPRequest,
        signer_cert: Certificate
    ) -> BasicOCSPResponse:
        ocsp_res_data = self._ocsp_cache.get(ocsp_req_data)
        if ocsp_res_data:
            cache = 'hit'
        else:
            ocsp_res_data = self._request_ocsp(url, ocsp_req_data)
            cache = 'miss'

        ocsp_basic_res = load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)

        if cache == 'miss':
            next_update = ocsp_basic_res['tbsResponseData']['responses'][0]['nextUpdate']
            if next_update:
                self._ocsp_cache.set(ocsp_req_data, ocsp_res_data, next_update)

        return ocsp_basic_res

    @abc.abstractmethod
    def _download_ocsp(self, url: bytes, ocsp_req_data: DerOCSPRequest) -> DerOCSPResponse:
        raise NotImplementedError

    def download_cert(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        for url in urls:
            if cert_res := self._file_cache.get(url):
                cache = 'hit'
                break
        else:
            cache = 'miss'
            excs = []
            for url in urls:
                try:
                    cert_res = self._download_cert(url)
                    break
                except TLSServiceError as exc:
                    excs.append(exc)
                    continue
            else:
                e = "all URLs failed"
                raise TLSServiceErrorGroup(e, excs)

        cert = load_verify_cert(cert_res)

        if cache == 'miss':
            next_update = ...
            if next_update:
                self._file_cache.set(url, cert_res, next_update)

        return cert

    @abc.abstractmethod
    def _download_cert(
        self,
        urls: Sequence[bytes]
    ) -> DerCertificate:
        raise NotImplementedError

    def download_crl(self, urls):
        raise NotImplementedError("todo")  # noqa: EM101

    @abc.abstractmethod
    def _download_crl(
        self,
        urls: Sequence[bytes]
    ) -> DerCRL:
        raise NotImplementedError
