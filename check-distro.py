#!/usr/bin/env python3

import errno
import os
import sys

for location in sys.argv[1:]:
  if os.path.isfile(location):
    sys.exit(0)

sys.exit(errno.ENOENT)
