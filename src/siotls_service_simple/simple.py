from siotls.service import TLSService
from siotls.utils import intbyte

from .safe_request import safe_request


class SimpleService(TLSService):
    def _download_cert(self, url):
        return safe_request(
            url,
            response_content_type=b'application/pkix-cert',
            response_max_length=intbyte('64kiB'),  # longest cert chain I have is 16kiB
        )

    def _download_crl(self, url):
        return safe_request(
            url,
            response_content_type=b'application/pkix-crl',
            response_body_max_length=intbyte('16MiB')  # longest crl I have (DigitCert) is 7MiB
        )

    def _download_ocsp(self, url, ocsp_req_data):
        return safe_request(
            url,
            ocsp_req_data,
            request_content_type = b'application/ocsp-request',
            request_body_max_length = intbyte(1024),
            response_content_type = b'application/ocsp-response',
            response_body_max_length = intbyte('32kiB'),  # longest ocsp res I have is 12kiB
        )
