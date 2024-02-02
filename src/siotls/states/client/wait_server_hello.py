from siotls.ciphers import cipher_suite_registry
from siotls.configuration import TLSNegociatedConfiguration
from siotls.contents import ChangeCipherSpec, alerts
from siotls.crypto.key_share import resume as key_share_resume
from siotls.iana import (
    ContentType,
    ExtensionType,
    HandshakeType,
    HandshakeType_,
    HeartbeatMode,
    MaxFragmentLengthOctets,
)

from .. import State
from . import ClientWaitEncryptedExtensions


class ClientWaitServerHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_server_hello = self.nconfig is None

    def process(self, content):
        if content.content_type != ContentType.HANDSHAKE:
            e = "Can only receive Handshake in this state."
            raise alerts.UnexpectedMessage(e)
        if self._is_first_server_hello:
            if content.msg_type != HandshakeType.SERVER_HELLO:
                e =("Can only receive ServerHello or HelloRetryRequest "
                    "in this state.")
                raise alerts.UnexpectedMessage(e)
        else:
            if content.msg_type is not HandshakeType.SERVER_HELLO:
                e = "Can only receive ServerHello in this state."
                raise alerts.UnexpectedMessage(e)

        if content.cipher_suite not in self.config.cipher_suites:
            e =(f"The server's selected {content.cipher_suite} wasn't offered "
                f"in ClientHello: {self.config.cipher_suites}")
            raise alerts.IllegalParameter(e)

        if self._is_first_server_hello:
            self.nconfig = TLSNegociatedConfiguration(content.cipher_suite)
            self._cipher = cipher_suite_registry[content.cipher_suite](
                'client', self.config.log_keys, self._client_unique)
            self._transcript.post_init(self._cipher.digestmod)
            self._send_content(ChangeCipherSpec())

        if content.msg_type is HandshakeType_.HELLO_RETRY_REQUEST:
            self._process_hello_retry_request(content)
        else:
            self._process_server_hello(content)

    def _process_hello_retry_request(self, hello_retry_request):
        from . import ClientStart

        key_share = hello_retry_request.extensions.get(ExtensionType.KEY_SHARE)
        if not key_share:
            e = "Missing Key Share in HelloRetryRequest"
            raise alerts.MissingExtension(e)
        if key_share.selected_group not in self.config.key_exchanges:
            e =(f"The server's selected {key_share.selected_group} wasn't "
                f"offered in ClientHello: {self.config.key_exchanges}")
            raise alerts.IllegalParameter(e)

        # make sure we select the algorithms selected by the server
        self.config.cipher_suites = [hello_retry_request.cipher_suite]
        self.config.key_exchanges = [key_share.selected_group]

        if cookie := hello_retry_request.extensions.get(ExtensionType.COOKIE):
            self._cookie = cookie.cookie

        self._transcript.do_hrr_dance()

        self._move_to_state(ClientStart)
        self.connection.initiate_connection()

    def _process_server_hello(self, server_hello):
        self._server_unique = server_hello.random
        shared_key = self._negociate_extensions(server_hello.extensions)
        self._cipher.skip_early_secrets()
        self._cipher.derive_handshake_secrets(shared_key, self._transcript.digest())
        self._move_to_state(ClientWaitEncryptedExtensions)

    def _negociate_extensions(self, server_extensions):
        def negociate(ext_name, *args, **kwargs):
            ext_type = getattr(ExtensionType, ext_name.upper())
            ext = server_extensions.get(ext_type)
            meth = getattr(self, f'_negociate_{ext_name}')
            return meth(ext, *args, **kwargs)

        shared_key = negociate('key_share', self._key_shares)
        negociate('max_fragment_length')
        negociate('application_layer_protocol_negotiation')
        negociate('heartbeat')
        return shared_key

    def _negociate_key_share(self, key_share_ext, my_private_keys):
        if not key_share_ext:
            raise alerts.MissingExtension(ExtensionType.KEY_SHARE)
        elif key_share_ext.group not in my_private_keys:
            e =(f"The server's selected {key_share_ext.selected_group} was "
                f"not offered in ClientHello: {self.config.key_exchanges}")
            raise alerts.IllegalParameter(e)
        else:
            shared_key, _ = key_share_resume(
                key_share_ext.group,
                my_private_keys[key_share_ext.group],
                key_share_ext.client_shares[key_share_ext.group],
            )
            self.nconfig.key_exchanges = key_share_ext.group
            return shared_key

    def _negociate_max_fragment_length(self, mfl_ext):
        if not mfl_ext:
            self.nconfig.max_fragment_length = MaxFragmentLengthOctets.MAX_16384
        elif mfl_ext.octets != self.config.max_fragment_length:
            try:
                code = self.config.max_fragment_length.to_code()
            except ValueError:
                code = None
            e =(f"The server's selected {mfl_ext.code} "
                f"wasn't offered in ClientHello: {code}")
            raise alerts.IllegalParameter(e)
        else:
            self.nconfig.max_fragment_length = mfl_ext.octets

    def _negociate_application_layer_protocol_negotiation(self, alpn_ext):
        if not alpn_ext:
            return
        elif length := len(alpn_ext.protocol_name_list) != 1:
            e =("Invalid Application Layer Protocol Negociation (ALPN) "
                f"response. Expected 1 protocol, {length} found.")
            raise alerts.IllegalParameter(e)
        elif alpn_ext.protocol_name_list[0] not in self.config.alpn:
            e =("The server's selected Application Layer Protocol (ALPN) "
                f"{alpn_ext.protocol_name_list[0]!r} wasn't offered in "
                f"ClientHello: {self.config.alpn}")
            raise alerts.IllegalParameter(e)
        else:
            self.nconfig.alpn = alpn_ext.protocol_name_list[0]

    def _negociate_heartbeat(self, heartbeat_ext):
        if not heartbeat_ext:
            self.nconfig.can_send_heartbeat = False
            self.nconfig.can_echo_heartbeat = False
        else:
            self.nconfig.can_send_heartbeat = (
                heartbeat_ext.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
