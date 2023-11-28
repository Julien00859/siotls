from siotls.secrets import TLSSecrets
from siotls.crypto.key_share import resume as key_share_resume
from siotls.configuration import TLSNegociatedConfiguration
from siotls.contents import alerts, ChangeCipherSpec
from siotls.iana import (
    ContentType,
    HandshakeType,
    HandshakeType_,
    HeartbeatMode,
    ExtensionType,
    MaxFragmentLengthOctets,
)
from .. import State
from . import ClientWaitEncryptedExtensions


class ClientWaitServerHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_server_hello = not bool(self._transcript_hash)

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
            self._secrets = TLSSecrets(
                self.nconfig.digestmod,
                max(8, self.nconfig.ciphermod.nonce_length_min),
            )
            self._transcript_hash = self.nconfig.digestmod(self._last_client_hello)
            self._last_client_hello = None
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

        # RFC 8446 4.4.1 shenanigans regarding HelloRetryRequest
        self._transcript_hash = self.nconfig.digestmod(b''.join([
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            self.nconfig.digestmod().digest_size.to_bytes(3, 'big'),
            self._transcript_hash.digest(),
            self._last_server_hello,
        ]))
        self._last_server_hello = None

        self._move_to_state(ClientStart)
        self.connection.initiate_connection()

    def _process_server_hello(self, server_hello):
        self._server_unique = server_hello.random
        shared_key = self._negociate_extensions(server_hello.extensions)

        self._secrets.skip_early_secrets()
        (cli_hs_key, cli_hs_iv, srv_hs_key, srv_hs_iv) = \
            self.secrets.compute_handshake_secrets(shared_key, self._transcript_hash.digest())
        self._read_cipher = self.nconfig.cipher(cli_hs_key)
        self._write_cipher = self.nconfig.cipher(srv_hs_key)
        self._reset_nonces(cli_hs_iv, srv_hs_iv)

        self._move_to_state(ClientWaitEncryptedExtensions)

    def _negociate_extensions(self, server_extensions):
        ET = ExtensionType
        try:
            key_share_ext = server_extensions[ET.KEY_SHARE]
        except KeyError as ext:
            raise alerts.MissingExtension() from ext
        shared_key = self._negociate_key_share(key_share_ext, self._key_exchange_privkeys)
        self._negociate_mfl(server_extensions.get(ET.MAX_FRAGMENT_LENGTH))
        self._negociate_alpn(server_extensions.get(ET.APPLICATION_LAYER_PROTOCOL_NEGOTIATION))
        self._negociate_heartbeat(server_extensions.get(ET.HEARTBEAT))

    def _negociate_key_share(self, key_share_ext, my_private_keys):
        if not key_share_ext:
        elif key_share_ext.group not in self._key_exchange_privkeys:
            e =(f"The server's selected {key_share_ext.selected_group} was "
                f"not offered in ClientHello: {self.config.key_exchanges}")
            raise alerts.IllegalParameter(e)
        shared_key, _ = key_share_resume(
            key_share_ext,
            my_private_keys[key_share_ext],
            key_share_ext.client_shares[key_share_ext],
        )
        self.nconfig.key_exchange = key_share_ext.group
        return shared_key

    def _negociate_mfl(self, mfl_ext):
        if not mfl_ext:
            self.nconfig.max_fragment_length = MaxFragmentLengthOctets.MAX_16384
        elif mfl_ext.octets != self.config.max_fragment_length:
            try:
                code = self.config.max_fragment_length.to_code()
            except ValueError:
                code = None
            e =(f"The server's selected {mfl_ext.code} wasn't offered "
                f"in ClientHello: {code}")
            raise alerts.IllegalParameter(e)
        else:
            self.nconfig.max_fragment_length = mfl_ext.octets

    def _negociate_alpn(self, alpn_ext):
        if not alpn_ext:
            self.nconfig.alpn = None
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
                self.config.can_send_heartbeat and
                heartbeat_ext.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
