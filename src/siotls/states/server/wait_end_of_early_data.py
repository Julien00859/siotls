from .. import State


class ServerWaitEndOfEarlyData(State):
    can_receive = True
    can_send = True
    can_send_application_data = True
