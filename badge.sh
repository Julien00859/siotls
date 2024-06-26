#!/usr/bin/env bash
set -euxo pipefail
SIOTLS_INTEGRATION=1
SIOTLS_SLOW=1
unittest-xml-reporting --output-file .coverage.unittest.xml
coverage run --source src/ --branch -m unittest
coverage xml
genbadge tests -i .coverage.unittest.xml
genbadge coverage -i coverage.xml
