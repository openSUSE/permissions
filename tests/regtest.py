#!/usr/bin/python3

import sys

from base import ChkstatRegtest
from tests import tests

test = ChkstatRegtest()
res = test.run(tests)
sys.exit(res)
