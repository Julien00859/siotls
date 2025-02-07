import logging
from datetime import UTC, datetime, timedelta

from pyasn1_modules.rfc5280 import Certificate

from siotls.service import FileStore, SieveCache, TLSService
from siotls.service.ocsp import load_verify_ocsp
from siotls.utils import intbyte

from . import TLSServiceError, TLSServiceErrorGroup
from .safe_request import safe_request

logger = logging.getLogger(__package__)


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



class SimpleService(TLSService):
    def __init__(self):
        self._ocsp_cache = _CacheHelper(SieveCache())
        self._file_cache = _CacheHelper(FileStore())

    def request_ocsp(self, url: str, ocsp_req_data: bytes, signer_cert: Certificate):
        if ocsp_res_data := self._ocsp_cache.get(ocsp_req_data):
            return ocsp_res_data

        ocsp_res_data = safe_request(
            url,
            ocsp_req_data,
            request_content_type = b'application/ocsp-request',
            request_body_max_length = intbyte(1024),
            response_content_type = b'application/ocsp-response',
            response_body_max_length = intbyte('32kiB')  # longest ocsp res I have is 12kiB
        )
        ocsp_basic_res = load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)

        next_update = ocsp_basic_res['tbsResponseData']['responses'][0]['nextUpdate']
        if next_update:
            self._ocsp_cache.set(ocsp_req_data, ocsp_res_data, next_update)

        return ocsp_res_data, ocsp_basic_res

    def download_crl(self, *a, **kw):
        raise NotImplementedError("todo")  # noqa: EM101
        safe_request(
            ...,
            response_content_type=b'application/pkix-crl',
            response_body_max_length=intbyte('16MiB')  # longest crl I have (DigitCert) is 7MiB,
        )

    def download_cert(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        for url in urls:
            if cert := self._cache_get(url):
                # TODO: verify that is hasn't been revoked since then
                return cert

        excs = []
        for url in urls:
            try:
                cert_res = safe_request(
                    url,
                    response_content_type=b'application/pkix-cert',
                    response_max_length=intbyte('64kiB'),  # longest cert chain I have is 16kiB
                )
                break
            except TLSServiceError as exc:
                excs.append(exc)
                continue
        else:
            e = "all URLs failed"
            raise TLSServiceErrorGroup(e, excs)

        try:
            cert = load_der_certificate(cert_res)
        except ValueError as exc:
            e = "error while loading certificate"
            raise TLSServiceError(e) from exc

        return cert_res, cert
