import logging
from ipaddress import ip_address
from itertools import pairwise

from cryptography import x509

from siotls.contents import alerts
from siotls.contents.handshakes.certificate import X509
from siotls.crypto.crl import get_crl_urls, is_revoked, load_crl
from siotls.crypto.ocsp import get_ocsp_url, make_ocsp_request, validate_ocsp
from siotls.iana import (
    CertificateStatusType,
    CertificateType,
    ContentType,
    ExtensionType,
    HandshakeType,
)
from siotls.services import TLSServiceError

from .. import State
from . import ClientWaitCertificateVerify

logger = logging.getLogger(__name__)


class ClientWaitCertificate(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def __init__(self, connection, must_authentify):
        super().__init__(connection)
        self._must_authentify = must_authentify

    def process(self, content):
        if (content.content_type != ContentType.HANDSHAKE
            or content.msg_type is not HandshakeType.CERTIFICATE):
            super().process(content)
            return

        if self.config.require_peer_authentication:
            if not content.certificate_list:
                e = "missing certificate"
                raise alerts.BadCertificate(e)
        self._check_certificate_types(content.certificate_list)
        match self.nconfig.server_certificate_type:
            case CertificateType.X509:
                self._process_x509(content)
            case CertificateType.RAW_PUBLIC_KEY:
                self._process_raw_public_key(content)
            case _:
                raise NotImplementedError

        self._move_to_state(
            ClientWaitCertificateVerify,
            must_authentify=self._must_authentify,
            certificate_transcript_hash=self._transcript.digest(),
        )

    def _check_certificate_types(self, certificate_entries):
        bad_entries = (
            entry
            for entry in certificate_entries
            if entry.certificate_type != self.nconfig.server_certificate_type
        )
        if bad_entry := next(bad_entries, None):
            e =(f"expected {self.nconfig.server_certificate_type} "
                f"but found {bad_entry.certificate_type}")
            raise alerts.UnsupportedCertificate(e)

    def _process_x509(self, content):
        self.nconfig.peer_certificate = content.certificate_list[0].certificate
        if self.config.require_peer_authentication:
            fullchain = self._verify_chain(content.certificate_list)
            if self.config.static_revocation_list:
                self._verify_static_revocation(content.certificate_list)
            certificate_entries = sorted(
                content.certificate_list,
                key=lambda entry: fullchain.index(entry.certificate)
            )
            if len(certificate_entries) < len(fullchain):
                ca_cert = fullchain[len(certificate_entries)]
                certificate_entries.append(X509(ca_cert, ()))
            for entry, issuer in pairwise(certificate_entries):
                entry_cert = entry.certificate
                issuer_cert = issuer.certificate
                status = entry.extensions.get(ExtensionType.STATUS_REQUEST)
                if status and status.status_type == CertificateStatusType.OCSP:
                    self._verify_status_ocsp_stapling(
                        entry_cert, issuer_cert, status.ocsp_response)
                if self.config.ocsp_service and (ocsp_url := get_ocsp_url(entry_cert)):
                    self._verify_status_ocsp(entry_cert, issuer_cert, ocsp_url)
                if self.config.crl_service and (crl_urls := get_crl_urls(entry_cert)):
                    self._verify_status_crl(entry_cert, issuer_cert, crl_urls)

    def _verify_chain(self, certificate_entries):
        leaf, *intermediates = (e.certificate for e in certificate_entries)
        try:
            return self._get_verifier().verify(leaf, intermediates)
        except x509.verification.VerificationError as exc:
            # TODO: CertificateExpired, but cryptography seems to lack it
            raise alerts.BadCertificate from exc

    def _get_verifier(self):
        if not self.server_hostname:
            # TODO: implement a a subject-free "build_server_verifier",
            # using "build_client_verifier" is bad because it checks for
            # EKU=Client instead of of EKU=Server... meh.
            return self.config.policy_builder.build_client_verifier()
        try:
            server_ip = ip_address(self.server_hostname)
        except ValueError:
            subject = x509.DNSName(self.server_hostname)
        else:
            subject = x509.IPAddress(server_ip)
        return self.config.policy_builder.build_server_verifier(subject)

    def _verify_static_revocation(self, certificate_entries):
        for entry in certificate_entries:
            if is_revoked(self.config.static_revocation_list, entry.certificate):
                e = f"{entry.certificate} found in static revocation list"
                raise alerts.CertificateRevoked(e)

    def _verify_status_ocsp_stapling(self, entry, issuer, ocsp_res):
        ocsp_req = make_ocsp_request(entry, issuer)
        try:
            validate_ocsp(issuer, ocsp_req, ocsp_res)
        except ValueError as exc:
            raise alerts.BadCertificateStatusResponse from exc

    def _verify_status_ocsp(self, entry, issuer, ocsp_url):
        ocsp_req = make_ocsp_request(entry, issuer)
        try:
            ocsp_res = self.config.ocsp_service.request(ocsp_url, ocsp_req)
        except TLSServiceError as exc:
            raise alerts.BadCertificateStatusResponse from exc
        try:
            valid_until = validate_ocsp(issuer, ocsp_req, ocsp_res)
        except ValueError as exc:
            self.config.ocsp_service.delete(ocsp_req)
            raise alerts.BadCertificateStatusResponse from exc
        self.config.ocsp_service.save(valid_until, ocsp_req, ocsp_res)

    def _verify_status_crl(self, entry, issuer, crl_urls):
        try:
            crl_url, crl_der = self.config.crl_service.request(crl_urls)
        except TLSServiceError as exc:
            raise alerts.CertificateUnknown from exc
        try:
            crl = load_crl(issuer, crl_der)
        except ValueError as exc:
            self.config.crl_service.delete(crl_url)
            raise alerts.CertificateUnknown from exc
        else:
            self.config.crl_service.save(crl_url, crl_der, crl.next_update_utc)
        if is_revoked(crl, entry):
            e = f"{entry} found in online revocation list"
            raise alerts.CertificateRevoked(e)

    def _process_raw_public_key(self, content):
        public_key = content.certificate_list[0].public_key
        self.nconfig.peer_public_key = public_key
        if (self.config.require_peer_authentication
            and public_key not in self.config.trusted_public_keys()
        ):
            e = "untrusted raw public key"
            raise alerts.BadCertificate(e)
