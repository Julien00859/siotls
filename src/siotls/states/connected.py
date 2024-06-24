from siotls.iana import ContentType

from . import State


class Connected(State):
    can_receive = True
    can_send = True
    can_send_application_data = True

    def process(self, message):
        if message.content_type != ContentType.APPLICATION_DATA:
            super().process(message)
            return

        self._application_data.extend(message.content_data)
