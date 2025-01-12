import logging
import random

from siotls.services import TLSService, TLSServiceError, TLSServiceErrorGroup
from siotls.utils import intbyte
from siotls.x509 import (
    load_der_certificate,
    load_der_ocsp_basic_response,
    load_der_ocsp_response,
    oid,
)

from ._mixins import CacheMixin, RequestMixin

logger = logging.getLogger(__package__)


"""
    request_content_type: bytes
    request_body_max_length: int
    response_content_type: bytes
    response_body_max_length: int
"""


class OCSPService(TLSService, CacheMixin, RequestMixin):
    request_content_type = b'application/ocsp-request'
    request_body_max_length = intbyte(1024)

    response_content_type = b'application/ocsp-response'
    response_body_max_length = intbyte('32kiB')  # longest ocsp res I have is 12kiB

    def request(self, url, ocsp_req):
        if ocsp_res := self._cache_get(ocsp_req):
            return ocsp_res

        ocsp_res = self._request(url, ocsp_req)
        try:
            ocsp = load_der_ocsp_response(ocsp_res)
            res_type_oid = oid.from_pyasn1(ocsp['responseBytes']['responseType'])
            if res_type_oid != oid.OCSPResponseType.OCSP_BASIC:
                e = f"unsupported OCSP response type {res_type_oid!r}"
                raise TLSServiceError(e)
            ocsp_basic = load_der_ocsp_basic_response(
                ocsp['responseBytes']['response'].asOctets())
        except ValueError as exc:
            e = "error while loading OCSP response"
            raise TLSServiceError(e) from exc

        # TODO: verify the OCSP response signature before using its data
        logger.warning("TODO: verify the OCSP response signature before using its data")
        nextUpdate = ocsp_basic['tbsResponseData']['responses'][0]['nextUpdate']
        if nextUpdate:
            self._cache_set(ocsp_req, ocsp_res, nextUpdate)

        return ocsp_res

class CRTService(TLSService, RequestMixin, CacheMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-cert'
    response_max_length = intbyte('64kiB')  # longest cert chain I have is 16kiB

    def request(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        if len(urls) == 1:
            return urls[0], self._request_single(urls[0])

        for url in urls:
            if cert := self._cache_get(url):
                return url, cert

        # Trying each URL sequentially isn't very effective... Ideally
        # we should do as many concurrent happy-eyeballs (RFC8305) as
        # there are URLs. So we can download from the single best one.
        random.shuffle(urls)  # don't always reach for the first one
        excs = []
        for url in urls:
            try:
                return self._process(self._request(url))
            except TLSServiceError as exc:
                excs.append(exc)
                continue
        e = "all URLs failed"
        raise TLSServiceErrorGroup(e, excs)

    def _process(self, cert_res):
        try:
            cert = load_der_certificate(cert_res)
        except ValueError as exc:
            e = "error while loading certificate"
            raise TLSServiceError(e) from exc

        return cert_res, cert



class CRLService(TLSService, RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-crl'
    response_max_length = intbyte('16MiB')  # longest crl I have (DigitCert) is 7MiB

