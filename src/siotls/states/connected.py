from siotls.iana import ContentType, HandshakeType

from . import State


class Connected(State):
    can_receive = True
    can_send = True
    can_send_application_data = True

    def process(self, message):
        if message.content_type == ContentType.APPLICATION_DATA:
            self._application_data.extend(message.content_data)
            return
        if message.content_type == ContentType.HANDSHAKE:
            if message.msg_type == HandshakeType.NEW_SESSION_TICKET:
                self._process_new_session_ticket(message)
                return
            if message.msg_type == HandshakeType.KEY_UPDATE:
                self._process_key_update(message)
                return

        super().process(message)

    def _process_new_session_ticket(self, message):
        ...

    def _process_key_update(self, message):
        raise NotImplementedError
