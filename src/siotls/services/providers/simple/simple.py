import logging

from siotls.services import TLSService, TLSServiceError
from siotls.utils import intbyte
from siotls.x509 import load_der_ocsp_basic_response, load_der_ocsp_response, oid

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
    request_body_max_length = intbyte(512)

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

class CRTService(TLSService, RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-cert'
    response_max_length = intbyte('64kiB')  # longest cert chain I have is 16kiB

    def request(self, url):


class CRLService(TLSService, RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-crl'
    response_max_length = intbyte('16MiB')< 1 << 24  # 16MiB, longest crl I have (DigitCert) is 7MiB

