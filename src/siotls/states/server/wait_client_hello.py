from .. import State


class ServerWaitClientHello(State):
    can_send_application_data = False
