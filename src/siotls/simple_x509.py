import base64
import typing
from dataclasses import dataclass
from datetime import datetime
from itertools import islice

import asn1

oid = typing.NewType('oid', str)
OID_COMMON_NAME = oid('2.5.4.3')

NULL = asn1.Tag(asn1.Numbers.Null, asn1.Types.Primitive, asn1.Classes.Universal)

datetime_formats = {
    asn1.Numbers.UTCTime: '%y%m%d%H%M%S%z',
    asn1.Numbers.GeneralizedTime: '%Y%m%d%H%M%S%z',
}


@dataclass(frozen=True)
class SimpleCertificate:
    version: int
    serial: int
    signature: oid
    issuer: dict[oid, str]
    not_before_utc: datetime
    not_after_utc: datetime
    subject: dict[oid, str]

    @property
    def subject_common_name(self):
        return self.subject['2.5.4.3']

    @property
    def issuer_common_name(self):
        return self.issuer['2.5.4.3']


def load_pem_x509_certificate(data):
    lines = data.splitlines()
    if lines[0] != b'-----BEGIN CERTIFICATE-----':
        e = "file must begin with -----BEGIN CERTIFICATE-----"
        raise ValueError((e, lines[0]))
    if lines[-1] != b'-----END CERTIFICATE-----':
        e = "file must end with -----END CERTIFICATE-----"
        raise ValueError(e)

    datader = base64.b64decode(b''.join(islice(lines, 1, len(lines) - 1)))
    return load_der_x509_certificate(datader)


def load_der_x509_certificate(data):
    cert = {}

    decoder = asn1.Decoder()
    decoder.start(data)

    decoder.enter()
    decoder.enter()

    tag = decoder.peek()
    if tag.cls == asn1.Classes.Context:
        decoder.enter()
        cert['version'] = decoder.read()[1]
        decoder.leave()
    else:
        cert['version'] = 0

    cert['serial'] = decoder.read()[1]

    decoder.enter()
    cert['signature'] = decoder.read()[1]
    if decoder.read() != (NULL, None):
        e = "expected a single signature"
        raise ValueError(e)
    decoder.leave()

    cert['issuer'] = {}
    decoder.enter()
    while decoder.peek():
        decoder.enter()
        decoder.enter()
        oid = decoder.read()[1]
        value = decoder.read()[1]
        cert['issuer'][oid] = value
        decoder.leave()
        decoder.leave()
    decoder.leave()

    decoder.enter()
    tag, value = decoder.read()
    cert['not_before_utc'] = datetime.strptime(value, datetime_formats[tag.nr])  # noqa: DTZ007
    tag, value = decoder.read()
    cert['not_after_utc'] = datetime.strptime(value, datetime_formats[tag.nr])  # noqa: DTZ007
    decoder.leave()

    cert['subject'] = {}
    decoder.enter()
    while decoder.peek():
        decoder.enter()
        decoder.enter()
        oid = decoder.read()[1]
        value = decoder.read()[1]
        cert['subject'][oid] = value
        decoder.leave()
        decoder.leave()
    decoder.leave()

    return SimpleCertificate(**cert), decoder


if __name__ == '__main__':
    import sys
    from pprint import pp

    def main(filepath):
        with open(filepath, 'rb') as file:
            header = file.read(27)
            file.seek(0)
            data = file.read()
        if header == b'-----BEGIN CERTIFICATE-----':
            return load_pem_x509_certificate(data)
        return load_der_x509_certificate(data)

    if len(sys.argv) != 2:  # noqa: PLR2004
        sys.exit(f"usage: python3 [-i] {sys.argv[0]} <file.pem>")

    cert, decoder = main(sys.argv[1])
    pp(cert)
