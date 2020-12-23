#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2012 - 2014 Red Hat, Inc.
#

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM

# This example asks settings service for all configured connections.


def print_values(setting, key, value, flags, data):
    print("  %s.%s: %s" % (setting.get_name(), key, value))


if __name__ == "__main__":
    # create Client object
    client = NM.Client.new(None)

    # get all connections
    connections = client.get_connections()

    # print the connections' details
    for c in connections:
        print("=== %s : %s ===" % (c.get_id(), c.get_path()))
        c.for_each_setting_value(print_values, None)
        print("\n")
