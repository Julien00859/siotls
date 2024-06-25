siotls
======

Sans-IO Python implementation of the TLS 1.3 (RFC 8446) protocol stack.

Disclaimer
----------

This project has not yet been reviewed by any security expert or cryptographer;
it is sure to be full of "landmines, dragons, and dinosaurs with laser guns,"
to cite the people at cryptography. In case you are one, please come and get in
touch with us!

While TLS 1.3 is excellent at giving guidance on how to set up and use the many
cryptography primitives in a safe way, there are still some important questions
that are left open. Questions such as "how many messages can we encrypt using
AES-CCM-8."

To help us navigate the rich world of secure communication, in addition to
RFC-8446 and the documents it references, we also studied:

* https://safecurves.cr.yp.to/
* https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014
* https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html
* https://cabforum.org/working-groups/server/baseline-requirements/documents/

Installation
------------

The package has not yet been published on PyPI, please download the source code
from main and build it using [`build`](https://build.pypa.io/en/latest/).
`build` creates artifacts under the `/dist` folder, the artifacts (`.whl`,
`.tar.gz` or `.zip`) can then be installed using `pip`.

Contributing
------------

Best it to start by opening an issue to discuss the things you wanna change or
improve. You can also just open a PR and write down everything in the PR
message.

### Installation

Clone the repository using git and place yourself inside the project root
directory. Create a new virtual environment and install the project in dev mode
inside.

    $ git clone https://github.com/Julien00859/siotls
    $ cd siotls
    $ python3 -m venv .env
    $ .env/bin/pip install -e .[dev]

Once all the dependencies downloaded and the project installed, you should be
able to run the unittests.

    $ .env/bin/python -m unittest

[`coverage`](https://coverage.readthedocs.io/en/latest/cmd.html) was installed
as part of the dev dependencies. It is a tool to compute the test coverage and
make sure that there is no blind spot. You run its `run` command once so it
gathers the information and then you print it out using its `html` command.

    $ .env/bin/coverage run --source src/ --branch -m unittest
    $ .env/bin/coverage html

Help us achieve a nice coverage!

### Tooling

For now we are only using ruff and isort. Don't loose too much time with those,
the maintainers are responsable for the housekeeping duty.

    $ ruff check src/ tests/
    $ isort --profile black -m 3 --ca src/ tests/
