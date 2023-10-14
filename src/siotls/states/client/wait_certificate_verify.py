from .. import State


class ClientWaitCertificateVerify(State):
    can_send_application_data = False
