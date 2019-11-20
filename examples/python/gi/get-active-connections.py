#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2014 Red Hat, Inc.
#

# This example lists currently active connections

import gi
gi.require_version('NM', '1.0')
from gi.repository import GLib, NM

if __name__ == "__main__":
    client = NM.Client.new(None)
    acons = client.get_active_connections()
    for ac in acons:
        print("%s (%s) - %s" % (ac.get_id(), ac.get_uuid(), ac.get_connection_type()))
    if len(acons) == 0:
       print("No active connections")


