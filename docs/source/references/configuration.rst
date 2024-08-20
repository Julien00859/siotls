Configuration
=============

.. module:: siotls.configuration

   .. autoclass:: TLSConfiguration
      :members:

   .. class:: TLSNegotiatedConfiguration

      The values agreed by both peers on a specific connection.
      Available at :attr:`siotls.connection.TLSConnection.nconfig`.

      .. attribute:: alpn
         :type: ALPNProtocol | None

      .. attribute:: can_echo_heartbeat
         :type: bool

      .. attribute:: can_send_heartbeat
         :type: bool

      .. attribute:: cipher_suite
         :type: CipherSuites

      .. attribute:: client_certificate_type
         :type: CertificateType

      .. attribute:: key_exchange
         :type: NamedGroup

      .. attribute:: max_fragment_length
         :type: MLFOctets

      .. attribute:: peer_certificate
         :type: Certificate

      .. attribute:: peer_public_key
         :type: PublicKeyTypes

      .. attribute:: peer_want_ocsp_stapling
         :type: bool

      .. attribute:: server_certificate_type
         :type: CertificateType

      .. attribute:: signature_algorithm
         :type: SignatureScheme

