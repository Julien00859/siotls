from siotls.iana import ContentType, HandshakeType

from .. import State
from . import ClientWaitCertificate


class ClientWaitCertCr(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def process(self, content):
        if (content.content_type != ContentType.HANDSHAKE
            or content.msg_type not in (
                HandshakeType.CERTIFICATE,
                HandshakeType.CERTIFICATE_REQUEST,
            )
        ):
            super().process(content)
            return

        self._move_to_state(
            ClientWaitCertificate,
            must_authentify=(content.msg_type == HandshakeType.CERTIFICATE_REQUEST),
        )
        if content.msg_type == HandshakeType.CERTIFICATE:
            self._state.process(content)
