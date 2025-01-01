# ruff: noqa: T201

import argparse
import re

from pyasn1_modules.rfc6960 import OCSPResponse

from . import loader, oid


def pformat(obj):
    return re.sub(r'\b(?:\d+\.)+\d+\b', lambda m: repr(oid(m[0])), str(obj))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--format', choices=('der', 'pem'))
    parser.add_argument('-c', '--class', dest='asn1class', choices=(
        'cert', 'certs', 'crl', 'ocsp-res', 'ocsp-req', 'pub-key', 'priv-key'), default='cert')
    parser.add_argument('file')
    options = parser.parse_args()

    if not options.format:
        with open(options.file, 'rb') as file:
            options.format = 'pem' if file.read(11) == b'-----BEGIN ' else 'der'

    x509_loader = {
        ('pem', 'cert'): loader.load_pem_x509_certificate,
        ('pem', 'certs'): loader.load_pem_x509_certificates,
        ('der', 'cert'): loader.load_der_x509_certificate,
        ('pem', 'crl'): loader.load_pem_x509_crl,
        ('der', 'crl'): loader.load_der_x509_crl,
        ('der', 'ocsp-req'): loader.load_der_ocsp_request,
        ('der', 'ocsp-res'): loader.load_der_ocsp_response,
        ('pem', 'priv_key'): loader.load_pem_private_key,
        ('der', 'priv_key'): loader.load_der_private_key,
        ('pem', 'pub_key'): loader.load_pem_public_key,
        ('der', 'pub_key'): loader.load_der_public_key,
    }[options.format, options.asn1class]

    with open(options.file, 'rb') as file:
        data = file.read()
        obj = x509_loader(data)

    return data, obj


if __name__ == '__main__':
    data, obj = main()
    print(pformat(obj))
    if (
        isinstance(obj, OCSPResponse)
        and (res_type_oid := obj['responseBytes']['responseType'].asTuple())
        and oid.from_tuple(res_type_oid) == oid.OCSPResponseType.OCSP_BASIC
    ):
        ocsp = loader.load_der_ocsp_basic_response(obj['responseBytes']['response'].asOctets())
        print(pformat(ocsp))
