import logging

from siotls.services import TLSService

from ._mixins import CacheMixin, RequestMixin

logger = logging.getLogger(__package__)


class OCSPService(TLSService, CacheMixin, RequestMixin):
    request_content_type = 'application/ocsp-request'
    response_content_type = 'application/ocsp-response'
    request_max_length = 512
    response_max_length = 1 << 15  # 32kiB, longest ocsp res I have is 12kiB

    def request(self, url, ocsp_req):
        if ocsp_res := self._cache_get(ocsp_req):
            return ocsp_res

        http_res, ocsp_res = self._request(url, ocsp_req)

        ocsp_res_obj = ...
        expire = ... # nextUpdate or now+maxage or expires
        if expire:
            self._cache_set(ocsp_req, ocsp_res, expire)

        return ocsp_res

    def delete(self, url, ocsp_req):  # noqa: ARG002
        self._cache_del(ocsp_req)

class CRTService(TLSService, RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = 'application/pkix-cert'
    response_max_length = 1 << 15  # 32kiB, longest cert chain I have is 16kiB


class CRLService(TLSService, RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = 'application/pkix-crl'
    response_max_length = 1 << 24  # 16MiB, longest crl I have (DigitCert) is 7MiB

