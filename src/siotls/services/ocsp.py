from pyasn1.codec.der.encoder import encode as der_encode

from siotls.crypto import TLSSignatureScheme
from siotls.x509.loader import (
    OCSPBasicResponse,
    load_der_ocsp_basic_response,
    load_der_ocsp_request,
    load_der_ocsp_response,
)
from siotls.x509.oid import OCSPResponseType, from_pyasn1 as oid_from_pyasn1
from siotls.x509.verifier import verify_ocsp_basic_response

from . import TLSServiceError


def load_verify_ocsp(der_ocsp_req, der_ocsp_res, signer_cert) -> OCSPBasicResponse:

    # load the basic response
    try:
        ocsp_res = load_der_ocsp_response(der_ocsp_res)
    except ValueError as exc:
        e = "malformed OCSP response"
        raise TLSServiceError(e) from exc
    if ocsp_res['responseStatus'] != 0:  # successful
        e = f"OCSP response status is not successful: {ocsp_res['responseStatus']}"
        raise TLSServiceError(e)
    ocsp_res_type = oid_from_pyasn1(OCSPResponseType, ocsp_res['responseBytes']['responseType'])
    if ocsp_res_type != OCSPResponseType.OCSP_BASIC:
        e = f"OCSP response type is not {OCSPResponseType.OCSP_BASIC}: {ocsp_res_type}"
        raise TLSServiceError(e)
    try:
        ocsp_basic_res = load_der_ocsp_basic_response(
            ocsp_res['responseBytes']['response'].asOctets())
    except ValueError as exc:
        e = "malformed OCSP basic response"
        raise TLSServiceError(e) from exc

    # verify the static informations
    ocsp_req = load_der_ocsp_request(der_ocsp_req)
    try:
        verify_ocsp_basic_response(ocsp_req, ocsp_basic_res, signer_cert)
    except ValueError as exc:
        e = "OCSP verification failed"
        raise TLSServiceError(e) from exc

    # verify the signature
    SignSuite = TLSSignatureScheme.for_signature_algo(ocsp_basic_res['signatureAlgorithm'])
    key_suite_ids = {
        suite.iana_id for suite in TLSSignatureScheme.for_key_algo(
            signer_cert['tbsCertificate']['subjectPublicKeyInfo']['algorithm'])
    }
    if SignSuite.iana_id not in key_suite_ids:
        e =("the OCSP basic response is signed using "
            f"{SignSuite.iana_id} but the CA's public key can only "
            f"produce signatures for {key_suite_ids}")
        raise TLSServiceError(e)
    SignSuite(
        public_key=der_encode(signer_cert['tbsCertificate']['subjectPublicKeyInfo'])
    ).verify(
        signature=ocsp_basic_res['signature'].asOctets(),
        message=der_encode(ocsp_basic_res['tbsResponseData']),
        alert=TLSServiceError("OCSP basic response signature verification failed")
    )

    return ocsp_basic_res
