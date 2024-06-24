from siotls.contents import alerts

from .connected import Connected


class Closed(Connected):
    can_receive = True
    can_send = True

    @property
    def can_send_application_data(self):
        return self.can_send

    def process(self, message):
        if not self.can_receive:
            e = f"cannot receive any message in state {self.name()}"
            raise alerts.UnexpectedMessage(e)
        return super().process(message)
