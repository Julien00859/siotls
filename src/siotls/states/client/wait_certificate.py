from .. import State


class ClientWaitCertificate(State):
    can_send_application_data = False
