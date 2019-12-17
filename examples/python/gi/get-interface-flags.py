#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2019 Red Hat, Inc.
#

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM

if __name__ == "__main__":
    client = NM.Client.new(None)
    devices = client.get_devices()

    for d in devices:
        print("{:<16} {:<16} {}".format(d.get_iface(),
                                        "(" + d.get_type_description() + ")",
                                        NM.utils_enum_to_str(NM.DeviceInterfaceFlags,
                                                             d.get_interface_flags())))
