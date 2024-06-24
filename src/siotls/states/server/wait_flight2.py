from .. import State


class ServerWaitFlight2(State):
    can_receive = True
    can_send = True
    can_send_application_data = True
