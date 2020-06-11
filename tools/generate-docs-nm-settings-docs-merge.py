#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1+

from __future__ import print_function

import os
import sys
import collections
import xml.etree.ElementTree as ET

###############################################################################

_setting_name_order = [
    "connection",
    "6lowpan",
    "802-1x",
    "adsl",
    "bluetooth",
    "bond",
    "bridge",
    "bridge-port",
    "cdma",
    "dcb",
    "dummy",
    "ethtool",
    "generic",
    "gsm",
    "infiniband",
    "ipv4",
    "ipv6",
    "ip-tunnel",
    "macsec",
    "macvlan",
    "match",
    "802-11-olpc-mesh",
    "ovs-bridge",
    "ovs-dpdk",
    "ovs-interface",
    "ovs-patch",
    "ovs-port",
    "ppp",
    "pppoe",
    "proxy",
    "serial",
    "sriov",
    "tc",
    "team",
    "team-port",
    "tun",
    "user",
    "vlan",
    "vpn",
    "vrf",
    "vxlan",
    "wifi-p2p",
    "wimax",
    "802-3-ethernet",
    "wireguard",
    "802-11-wireless",
    "802-11-wireless-security",
    "wpan",
]

def _setting_name_order_idx(name):
    try:
        return _setting_name_order.index(name)
    except ValueError:
        return len(_setting_name_order)

def key_fcn_setting_name(n1):
    return (_setting_name_order_idx(n1), n1)

def iter_keys_of_dicts(dicts, key = None):
    keys = set([k for d in dicts for k in d.keys()])
    return sorted(keys, key = key)

def node_to_dict(node, tag, key_attr):
    dictionary = collections.OrderedDict()
    if node is not None:
        for n in node.iter(tag):
            k = n.get(key_attr)
            assert(k is not None)
            dictionary[k] = n
    return dictionary

def node_get_attr(nodes, name):
    for n in nodes:
        if n is None:
            continue
        x = n.get(name, None)
        if x:
            return x
    return None

def node_set_attr(dst_node, name, nodes):
    x = node_get_attr(nodes, name)
    if x:
        dst_node.set(name, x)

###############################################################################

gl_only_from_first = False

argv = list(sys.argv[1:])
while True:
    if argv[0] == '--only-from-first':
        gl_only_from_first = True
        del argv[0]
        continue
    break
if len(argv) < 2:
    print("%s [--only-from-first] [OUT_FILE] [SETTING_XML [...]]" % (sys.argv[0]))
    exit(1)

gl_output_xml_file = argv[0]
gl_input_files = list(argv[1:])

###############################################################################

xml_roots = list([ET.parse(f).getroot() for f in gl_input_files])

assert(all([root.tag == 'nm-setting-docs' for root in xml_roots]))

settings_roots = list([node_to_dict(root, 'setting', 'name') for root in xml_roots])

root_node = ET.Element('nm-setting-docs')

for setting_name in iter_keys_of_dicts(settings_roots, key_fcn_setting_name):

    settings = list([d.get(setting_name) for d in settings_roots])

    if     gl_only_from_first \
       and settings[0] is None:
        continue

    properties = list([node_to_dict(s, 'property', 'name') for s in settings])

    if     gl_only_from_first \
       and not properties[0]:
        continue

    setting_node = ET.SubElement(root_node, 'setting')

    setting_node.set('name', setting_name)

    node_set_attr(setting_node, 'description', settings)
    node_set_attr(setting_node, 'name_upper', settings)

    for property_name in iter_keys_of_dicts(properties):

        properties_attrs = list([p.get(property_name) for p in properties])

        if     gl_only_from_first \
           and properties_attrs[0] is None:
            continue

        property_node = ET.SubElement(setting_node, 'property')
        property_node.set('name', property_name)
        property_node.set('name_upper', property_name.upper().replace('-', '_'))

        x = node_get_attr(properties_attrs, 'format')
        if x:
            property_node.set('type', x)
        else:
            node_set_attr(property_node, 'type', properties_attrs)

        node_set_attr(property_node, 'default', properties_attrs)
        node_set_attr(property_node, 'description', properties_attrs)

ET.ElementTree(root_node).write(gl_output_xml_file)
