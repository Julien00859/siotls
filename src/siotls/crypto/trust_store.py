import abc
from collections.abc import Sequence
from itertools import chain, islice, pairwise

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules.rfc5280 import AuthorityKeyIdentifier, Certificate

from siotls.x509.loader import load_der
from siotls.x509.oid import AKI, ExtensionOID, from_pyasn1 as oid_from_pyasn1

from .signature_schemes import TLSSignatureScheme


class TLSTrustStore(metaclass=abc.ABCMeta):
    def verify_chain(self, certificate_chain: Sequence[Certificate]):
        find_root_ca = (i for i, cert in enumerate(certificate_chain) if self.is_trusted(cert))
        if ca_index := next(find_root_ca, None):
            # cut off the chain at the first trusted certificate
            fullchain = islice(certificate_chain, 0, ca_index)
        else:
            # include the ca at the end of the chain
            ca_cert = self.find_authority(certificate_chain[-1])
            fullchain = chain(certificate_chain, (ca_cert,))

        for subject, issuer in pairwise(fullchain):
            issuer_pubkey = issuer['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']
            SignAlgo = TLSSignatureScheme.for_signature_algo(subject['signatureAlgorithm'])
            sign_algo = SignAlgo(public_key=issuer_pubkey.asOctets())
            sign_algo.verify(
                signature=subject['signature'].asOctets(),
                message=der_encode(subject['tbsCertificate'])
            )

    @abc.abstractmethod
    def is_trusted(self, certificate: Certificate):
        raise NotImplementedError

    def find_authority(self, certificate: Certificate):
        for ext in Certificate['tbsCertificate']['extensions']:
            if oid_from_pyasn1(ExtensionOID, ext['extnID']) == AKI:
                aki_ext = load_der(ext['extnValue'].asOctets(), AuthorityKeyIdentifier())
                aki = aki_ext['keyIdentifier'].asOctets()
                return self._find_authority_by_ski(aki)
        name = der_encode(certificate['tbsCertificate']['subject'])
        return self._find_authority_by_name(name)

    @abc.abstractmethod
    def _find_authority_by_name(self, name: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def _find_authority_by_ski(self, ski: bytes):
        raise NotImplementedError
