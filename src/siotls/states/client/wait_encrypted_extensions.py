from siotls.contents import alerts
from siotls.iana import (
    CertificateType,
    ContentType,
    ExtensionType,
    HandshakeType,
    HeartbeatMode,
    MaxFragmentLengthOctets,
)

from .. import State
from . import ClientWaitCertCr


class ClientWaitEncryptedExtensions(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def process(self, content):
        if (content.content_type != ContentType.HANDSHAKE
            or content.msg_type is not HandshakeType.ENCRYPTED_EXTENSIONS):
            super().process(content)
            return

        def negociate(ext_name, *args, **kwargs):
            ext_type = getattr(ExtensionType, ext_name.upper())
            ext = content.extensions.get(ext_type)
            meth = getattr(self, f'_negociate_{ext_name}')
            return meth(ext, *args, **kwargs)

        negociate('max_fragment_length')
        negociate('application_layer_protocol_negotiation')
        negociate('heartbeat')
        negociate('client_certificate_type')
        negociate('server_certificate_type')

        self._move_to_state(ClientWaitCertCr)

    def _negociate_max_fragment_length(self, mfl_ext):
        if not mfl_ext:
            self.nconfig.max_fragment_length = MaxFragmentLengthOctets.MAX_16384
        elif mfl_ext.octets != self.config.max_fragment_length:
            e = "the server-selected max fragment length wasn't offered"
            raise alerts.IllegalParameter(e)
        else:
            self.nconfig.max_fragment_length = mfl_ext.octets

    def _negociate_application_layer_protocol_negotiation(self, alpn_ext):
        if not alpn_ext:
            self.nconfig.alpn = None
            return
        elif (length := len(alpn_ext.protocol_name_list)) != 1:
            e =(f"the server selected {length} application layer"
                " protocols (ALPN) instead of 1")
            raise alerts.IllegalParameter(e)
        elif alpn_ext.protocol_name_list[0] not in self.config.alpn:
            e =("the server-selected application layer protocol (ALPN) "
                "wasn't offered")
            raise alerts.IllegalParameter(e)
        else:
            self.nconfig.alpn = alpn_ext.protocol_name_list[0]
    _negociate_alpn = _negociate_application_layer_protocol_negotiation

    def _negociate_heartbeat(self, heartbeat_ext):
        if not heartbeat_ext:
            self.nconfig.can_send_heartbeat = False
            self.nconfig.can_echo_heartbeat = False
        else:
            self.nconfig.can_send_heartbeat = (
                heartbeat_ext.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat

    def _negociate_client_certificate_type(self, ext):
        if not ext:
            self.nconfig.client_certificate_type = CertificateType.X509
        elif ext.certificate_type in self.config.certificate_types:
            self.nconfig.client_certificate_type = ext.certificate_type
        else:
            e = "the server-selected client certificate type wasn't offered"
            raise alerts.IllegalParameter(e)

    def _negociate_server_certificate_type(self, ext):
        if not ext:
            self.nconfig.server_certificate_type = CertificateType.X509
        elif ext.certificate_type in self.config.peer_certificate_types:
            self.nconfig.server_certificate_type = ext.certificate_type
        else:
            e = "the server-selected server certificate type wasn't offered"
            raise alerts.IllegalParameter(e)
