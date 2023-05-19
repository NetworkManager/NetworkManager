#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import print_function

import collections
import os
import sys
import xml.etree.ElementTree as ET

###############################################################################


DEBUG = os.environ.get("NM_GENERATE_DOCS_NM_SETTINGS_DOCS_MERGE_DEBUG", None) == "1"


def dbg(msg):
    if DEBUG:
        print("%s" % (msg,))


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


def iter_keys_of_dicts(dicts, key=None):
    keys = set([k for d in dicts for k in d.keys()])
    return sorted(keys, key=key)


def node_to_dict(node, tag, key_attr):
    dictionary = collections.OrderedDict()
    if node is not None:
        for n in node.iter(tag):
            k = n.get(key_attr)
            assert k is not None
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


def find_attr(properties_attrs, name):
    for p_attr in properties_attrs:
        if p_attr is None:
            continue
        p_attr = p_attr.find(name)
        if p_attr is not None:
            return p_attr


def find_description(properties_attrs):
    for p in properties_attrs:
        if p is None:
            continue

        # These are not attributes, but XML element.
        assert p.get("description", None) is None
        assert p.get("description-docbook", None) is None

        p_elem = p.find("description")
        p_elem_docbook = p.find("description-docbook")

        if p_elem is not None or p_elem_docbook is not None:
            if p_elem is None or p_elem_docbook is None:
                # invalid input!
                if p_elem:
                    s = ET.tostring(p_elem)
                else:
                    s = ET.tostring(p_elem_docbook)
                raise Exception(
                    "We expect both a <description> and <description-docbook> tag, but we only have %s"
                    % (s,)
                )
            return p_elem, p_elem_docbook

    return None, None


def find_deprecated(properties_attrs):
    for p in properties_attrs:
        if p is None:
            continue

        # These are not attributes, but XML element.
        assert p.get("deprecated", None) is None
        assert p.get("deprecated-docbook", None) is None

        # We don't expect a <deprecated-docbook> tag.
        assert p.find("deprecated-docbook") is None

        p_elem = p.find("deprecated")

        if p_elem is not None:
            # We require a "since" attribute
            assert p_elem.get("since", None) is not None
            return p_elem

    return None


###############################################################################

gl_only_from_first = False

gl_only_properties_from = None
gl_output_xml_file = None
gl_input_files = []


def usage_and_quit(exit_code):
    print(
        "%s [--only-properties-from SLECTOR_FILE] [OUT_FILE] [SETTING_XML [...]]"
        % (sys.argv[0])
    )
    exit(exit_code)


i = 1
special_args = True
while i < len(sys.argv):
    if special_args and sys.argv[i] in ["-h", "--help"]:
        usage_and_quit(0)
    elif special_args and sys.argv[i] == "--only-properties-from":
        i += 1
        gl_only_properties_from = sys.argv[i]
    elif special_args and sys.argv[i] == "--":
        special_args = False
    elif gl_output_xml_file is None:
        gl_output_xml_file = sys.argv[i]
    else:
        gl_input_files.append(sys.argv[i])
    i += 1
if len(gl_input_files) < 2:
    usage_and_quit(1)

###############################################################################

for f in gl_input_files:
    dbg("> input file %s" % (f))

xml_roots = [ET.parse(f).getroot() for f in gl_input_files]

assert all([root.tag == "nm-setting-docs" for root in xml_roots])


def skip_property(setting_name, property_name):
    return False


if gl_only_properties_from:
    xml_root = ET.parse(gl_only_properties_from).getroot()
    opf_setting_root = node_to_dict(xml_root, "setting", "name")
    opf_cache = {}

    def skip_property(setting_name, property_name):
        if setting_name not in opf_cache:
            s = opf_setting_root.get(setting_name)
            if s is not None:
                s = node_to_dict(s, "property", "name")
            opf_cache[setting_name] = s
        else:
            s = opf_cache[setting_name]
        if not s:
            return True
        if property_name is not None:
            p = s.get(property_name)
            if p is None:
                return True
        return False


settings_roots = [node_to_dict(root, "setting", "name") for root in xml_roots]

root_node = ET.Element("nm-setting-docs")

for setting_name in iter_keys_of_dicts(settings_roots, key_fcn_setting_name):

    dbg("> > setting_name: %s" % (setting_name))

    if skip_property(setting_name, None):
        dbg("> > > skip (only-properties-from)")
        continue

    settings = [d.get(setting_name) for d in settings_roots]

    properties = [node_to_dict(s, "property", "name") for s in settings]

    setting_node = ET.SubElement(root_node, "setting")

    setting_node.set("name", setting_name)

    node_set_attr(setting_node, "description", settings)
    node_set_attr(setting_node, "name_upper", settings)
    node_set_attr(setting_node, "alias", settings)

    dbg("> > > create node")

    for property_name in iter_keys_of_dicts(properties):

        dbg("> > > > property_name: %s" % (property_name))

        properties_attrs = [p.get(property_name) for p in properties]

        description, description_docbook = find_description(properties_attrs)
        deprecated = find_deprecated(properties_attrs)

        if skip_property(setting_name, property_name):
            dbg("> > > > skip (only-properties-from)")
            continue

        property_node = ET.SubElement(setting_node, "property")
        property_node.set("name", property_name)
        property_node.set("name_upper", property_name.upper().replace("-", "_"))

        dbg("> > > > > create node")

        x = node_get_attr(properties_attrs, "format")
        if x:
            property_node.set("type", x)
        else:
            node_set_attr(property_node, "type", properties_attrs)

        node_set_attr(property_node, "default", properties_attrs)
        node_set_attr(property_node, "alias", properties_attrs)

        if description_docbook is not None:
            property_node.insert(0, description_docbook)
        if description is not None:
            property_node.append(description)

        if deprecated is not None:
            property_node.insert(0, deprecated)

ET.ElementTree(root_node).write(gl_output_xml_file)
