import argparse
import logging
from siotls.__main__ import setup_logging

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='verbosity', action='count', default=0)
options, _ = parser.parse_known_args()

logging.basicConfig()
setup_logging(logging.WARNING - 10 * options.verbosity)
