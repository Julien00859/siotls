from .. import State


class ClientWaitServerHello(State):
    can_send_application_data = False
