siotls: sans-io TLS 1.3 for Python
==================================

**siotls** is a pure Python implementation of the TLS 1.3 protocol,
designed to offer a network-independent TLS library for the Python
ecosystem. It is fully self-contained, performing no I/O operations,
which allows seamless integration with any concurrency model or runtime
environment.

**Note**: siotls is not a cryptography library; it leverages external
libraries for all cryptographic operations.

Sans-IO Philosophy
------------------

siotls embraces the `Sans‑IO`_ movement, pioneered by Cory Benfield and
the `Hyper`_ team. This approach focuses on creating network protocol
implementations that are independent of network communications. While
the Hyper team tackled HTTP, siotls brings this philosophy to TLS.

siotls operates solely on bytes, leaving all socket operations to the
user. By controlling the flow of bytes to and from siotls, the users
retain the freedom to choose the socket library that best fits their
needs.

In this documentation
---------------------

.. grid:: 1 1 2 2

   .. grid-item:: :doc:`Tutorials <tutorials/index>`

      **Get started** with simple examples to run a TLS client or
      server.

   .. grid-item:: :doc:`How-to guides <guides/index>`

      **Step-by-step** instructions to benefit from advanced TLS 1.3
      features.

.. grid:: 1 1 2 2

   .. grid-item:: :doc:`Explanations <explanations/index>`

      **In-depth discussions** on security best-practices, TLS
      extensions and cryptography primitives.

   .. grid-item:: :doc:`References <references/index>`

      **Comprehensive API** documentation.

Comparison with Python’s ssl
----------------------------

Python’s standard library includes an `ssl`_ module that wraps the TLS
protocol stack provided by OpenSSL. While both the ssl module and siotls
offer TLS without direct I/O, key differences exist:

* **Protocol Stack and Cryptography**:
  The ssl module uses OpenSSL 1.1.1, whereas siotls implements its own
  protocol stack and aims to be compatible with multiple cryptography
  libraries.

* **Supported Protocol Versions**:
  The ssl module supports all versions of SSL and TLS that OpenSSL 1.1.1
  supports, while siotls is dedicated to TLS 1.3 only.

* **Language and Implementation**:
  The ssl module is implemented in C, whereas siotls is written entirely
  in Python.

* **Release Schedule and Policies**:
  The ssl module follows CPython’s release schedule and backward
  compatibility policies. siotls, being a separate project, adheres to
  its own timeline and policies.

* **Community and Maturity**:
  The ssl module is a well-established and widely used library,
  supported by a large community that includes security experts and
  organizations. In contrast, siotls is still in its early stages and is
  not yet as mature or battle-tested as the ssl module.

.. toctree::
   :maxdepth: 2
   :hidden:

   tutorials/index
   guides/index
   explanations/index
   references/index

.. _Sans‑IO: https://sans-io.readthedocs.io/
.. _Hyper: https://github.com/python-hyper
.. _ssl: https://docs.python.org/3/library/ssl.html#memory-bio-support
.. _RFC-8446: https://datatracker.ietf.org/doc/html/rfc8446
