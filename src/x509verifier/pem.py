import base64
import io
import re
from enum import IntEnum

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules.rfc5280 import Certificate, CertificateList

KNOWN_PEM_LABELS = (
    'CERTIFICATE', 'X509 CRL', 'CERTIFICATE REQUEST', 'PKCS7', 'CMS',
    'PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'ATTRIBUTE CERTIFICATE',
    'PUBLIC KEY',
)
LABEL_TO_CLASS = {
    'CERTIFICATE': Certificate,
    'X509 CRL': CertificateList,
}
PEM_LABEL_RE = re.compile(r'[!-,.-~]+(?:[\s-][!-,.-~]+)')

def is_valid_pem_label(label):
    """ Is :param:`label` a valid label according to RFC 7468 """
    if label == '':
        return True
    if label in KNOWN_PEM_LABELS:
        return True
    return re.fullmatch(PEM_LABEL_RE, label)


class _PemState(IntEnum):
    WAIT_BEGIN = 1
    WAIT_END = 2


def pem_decode(substrate, asn1Spec=None, *, multi=False):  # noqa: C901, N803
    asn1_objects = []
    state = _PemState.WAIT_BEGIN
    for lineno, line in enumerate(substrate.splitlines()):
        match state:
            case _PemState.WAIT_BEGIN:
                if line.startswith('-----BEGIN ') and line.endswith('-----'):
                    label = line[11:-5]
                    if not is_valid_pem_label(label):
                        e = f"invalid label at line {lineno}: {label!r}"
                        raise ValueError(e)
                    der_data = bytearray()
                    state = _PemState.WAIT_END

            case _PemState.WAIT_END:
                if line == f'-----END {label}-----':
                    asn1_obj, rest = der_decode(
                        io.BytesIO(der_data),
                        asn1Spec or LABEL_TO_CLASS.get(label, type(None))()
                    )
                    if rest:
                        e =(f"only {len(der_data) - len(rest)} bytes "
                            f"out of {len(der_data)} could be decoded "
                            f"for {label} at line {lineno}")
                        raise ValueError(e)
                    if not multi:
                        return asn1_obj
                    asn1_objects.append(asn1_obj)
                    state = _PemState.WAIT_BEGIN
                elif line.startswith('-----'):
                    e = f"invalid boundary at line {lineno}"
                    raise ValueError(e)
                else:
                    try:
                        der_data += base64.b64decode(line.rstrip())
                    except ValueError as exc:
                        e = f'{exc.args[0]} at line {lineno}'
                        raise ValueError(e) from None

    if state == _PemState.WAIT_END:
        e = f"end boundary {'-----END {label}-----'!r} not found"
        raise ValueError(e)
    elif not multi:
        e = f"begin boundary {'-----BEGIN [type]----'!r} not found"
        raise ValueError(e)

    return asn1_objects
