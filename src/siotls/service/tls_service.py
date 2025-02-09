import abc
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from pyasn1_modules.rfc5280 import Certificate, CertificateList
from pyasn1_modules.rfc6960 import BasicOCSPResponse

from siotls import TLSError, TLSErrorGroup
from siotls.contents import alerts
from siotls.service.ocsp import load_verify_ocsp
from siotls.x509.loader import (
    DerCertificate,
    DerCRL,
    DerOCSPRequest,
    DerOCSPResponse,
)

from .filestore import FileStore
from .sievecache import SieveCache


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

    def close(self):
        if hasattr(self._cache, 'close'):
            self._cache.close()


class TLSService(metaclass=abc.ABCMeta):
    def __init__(self, *, mem_cache=None, file_cache=None):
        self._mem_cache = _CacheHelper(mem_cache or SieveCache())
        self._file_cache = _CacheHelper(file_cache or FileStore())

    def close(self):
        self._mem_cache.close()
        self._file_cache.close()

    def get_cached_ocsp(
        self,
        ocsp_req_data: DerOCSPRequest,
        signer_cert: Certificate
    ) -> BasicOCSPResponse | None:
        if ocsp_res_data := self._mem_cache.get(ocsp_req_data):
            try:
                return load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)
            except TLSError:
                self._mem_cache.rem(ocsp_req_data)
        return None

    @abc.abstractmethod
    def download_ocsp(self, url: bytes, ocsp_req_data: DerOCSPRequest) -> DerOCSPResponse:
        raise NotImplementedError

    def request_ocsp(
        self,
        url: bytes,
        ocsp_req_data: DerOCSPRequest,
        signer_cert: Certificate
    ) -> BasicOCSPResponse:
        if cached_ocsp_basic_res := self.get_cached_ocsp(ocsp_req_data, signer_cert):
            return cached_ocsp_basic_res

        try:
            ocsp_res_data = self.download_ocsp(url, ocsp_req_data)
            ocsp_basic_res = load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)
        except alerts.Alert:
            raise
        except TLSError as exc:
            raise alerts.BadCertificateStatusResponse from exc

        next_update = ocsp_basic_res['tbsResponseData']['responses'][0]['nextUpdate']
        if next_update:
            self._mem_cache.set(ocsp_req_data, ocsp_res_data, next_update)

        return ocsp_basic_res


    def get_cached_cert(self, urls: Sequence[bytes]) -> Certificate | None:
        for url in urls:
            if cert_res := self._file_cache.get(url):
                try:
                    return load_verify_cert(cert_res)
                except TLSError:
                    self._file_cache.rem(url)
        return None

    @abc.abstractmethod
    def download_cert(self, url: bytes) -> DerCertificate:
        raise NotImplementedError

    def request_cert(self, urls: Sequence[bytes]) -> Certificate:
        if cert := self.get_cached_cert(urls):
            return cert

        if not urls:
            e = "no URLs"
            raise ValueError(e)

        excs = []
        for url in urls:
            try:
                cert_res = self.download_cert(url)
                cert = load_verify_cert(cert_res)
                break
            except alerts.Alert as exc:
                excs.append(exc)
            except TLSError as exc:
                exc_ = alerts.CertificateUnknown
                exc_.__cause__ = exc
                excs.append(exc_)
        else:
            e = "all URLs failed"
            raise TLSErrorGroup(e, excs)

        next_update = ...
        if next_update:
            self._file_cache.set(url, cert_res, next_update)

        return cert


    def get_cached_crl(self, urls: Sequence[bytes]) -> CertificateList:
        raise NotImplementedError("todo")  # noqa: EM101

    @abc.abstractmethod
    def download_crl(self, url: bytes) -> DerCRL:
        raise NotImplementedError

    def request_crl(self, urls) -> CertificateList:
        raise NotImplementedError("todo")  # noqa: EM101
