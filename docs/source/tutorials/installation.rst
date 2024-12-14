Installation
============

siotls is a typical pure-python library that can be installed via pip.
However, as it doesn't perform any cryptographic computation on its own,
you must pair siotls with an additional cryptographic library.

Openssl / Cryptography
----------------------

The `OpenSSL`_ software library is a robust, commercial-grade,
full-featured toolkit for general-purpose cryptography and secure
communication.

Citing the security experts at Latacora:

	There was a dark period between 2010 and 2016 where OpenSSL might
	not have been the right answer, but that time has passed. OpenSSL
	has gotten better, and, more importantly, OpenSSL is on-the-ball
	with vulnerability disclosure and response.

	Using anything besides OpenSSL will drastically complicate your
	system for little, no, or even negative security benefit. So just
	keep it simple.

The `cryptography`_ python library is a rust binding for openssl, it is
maintained by the Python Cryprographic Authority (PyCA), a group of
people that have been maintaining various high profiles cryptographic
libraries for python.

To use siotls with openssl/cryptography run:

.. code::

	pip install siotls[cryptography]

.. _OpenSSL: https://openssl-library.org/
.. _cryptography: https://cryptography.io/
