#!/usr/bin/python3

import sys

from base import PermctlRegtest
from tests import tests

test = PermctlRegtest()
res = test.run(tests)
sys.exit(res)
