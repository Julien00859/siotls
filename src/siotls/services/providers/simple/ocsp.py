import logging

from pyasn1_modules.rfc5280 import Certificate

from siotls.services import TLSService
from siotls.services.ocsp import load_verify_ocsp
from siotls.services.sievecache import SieveCache
from siotls.utils import intbyte

from ._mixins import CacheMixin, RequestMixin

logger = logging.getLogger(__package__)


class OCSPService(TLSService, CacheMixin, RequestMixin):
    cache_cls = SieveCache

    request_content_type = b'application/ocsp-request'
    request_body_max_length = intbyte(1024)

    response_content_type = b'application/ocsp-response'
    response_body_max_length = intbyte('32kiB')  # longest ocsp res I have is 12kiB

    def request(self, url: str, ocsp_req_data: bytes, signer_cert: Certificate):
        if ocsp_res_data := self._cache_get(ocsp_req_data):
            return ocsp_res_data

        ocsp_res_data = self._request(url, ocsp_req_data)
        ocsp_basic_res = load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)

        next_update = ocsp_basic_res['tbsResponseData']['responses'][0]['nextUpdate']
        if next_update:
            self._cache_set(ocsp_req_data, ocsp_res_data, next_update)

        return ocsp_res_data
