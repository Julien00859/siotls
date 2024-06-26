### ca

A ECDSA CA certificate. It features some x509 extensions commonly found in root
CA certificates. It is self-signed.

### client

A ECDSA client certificate. It features some x509 extensions commonly found in
web server certificates but with the CLIENT_AUTH EKU. It is signed by "ca".

### server

A ECDSA server certificate. It features some x509 extensions commonly found in
web server certificates. It is signed by "ca".


