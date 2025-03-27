#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright (C) 2022 Red Hat, Inc.
#

from __future__ import print_function
import xml.etree.ElementTree as ET
import argparse
import re
import sys

C_NS = "http://www.gtk.org/introspection/c/1.0"
CORE_NS = "http://www.gtk.org/introspection/core/1.0"
GLIB_NS = "http://www.gtk.org/introspection/glib/1.0"


def syms_from_gir(girfile):
    def xml_symbols(xml, types):
        ret = []
        for t in types:
            ret += xml.findall("./{%s}namespace/{%s}%s" % (CORE_NS, CORE_NS, t))
            ret += xml.findall("./{%s}namespace/*/{%s}%s" % (CORE_NS, CORE_NS, t))
        return ret

    girxml = ET.parse(girfile)
    c_syms = {}
    for sym in xml_symbols(girxml, ("constructor", "function", "method")):
        c_syms[sym.get("{%s}identifier" % C_NS)] = sym.get("version")

    for sym in xml_symbols(
        girxml, ("bitfield", "class", "enumeration", "interface", "record")
    ):
        get_type = sym.get("{%s}get-type" % GLIB_NS)
        if get_type is None:
            continue
        version = sym.get("version")

        if version is None:
            # FIXME: The get_type() functions should be exported in the same
            # version the type itself appeared. However, a large number of
            # classes lack Since: tags in their doc blocks. Fall back to using
            # the tag on _new() method for the test to be able to proceed
            # reasonably. This should be fixed eventually.
            constructor = sym.find("./{%s}constructor" % CORE_NS)
            if constructor is not None:
                version = constructor.get("version")

        c_syms[get_type] = version
    return c_syms


# Older Python doesn't have str.removesuffix()
def str_removesuffix(string, suffix):
    try:
        return string.removesuffix(suffix)
    except AttributeError:
        if string.endswith(suffix):
            return string[: -len(suffix)]
        else:
            return string


def syms_from_ver(verfile):
    c_syms = {}
    for line in open(verfile).readlines():
        line = line.strip()

        if line.endswith("{"):
            line = str_removesuffix(line, " {")
            m = re.search(r"^libnm_([0-9]+)_([0-9]+)_([0-9]+)$", line)
            if not m:
                continue
            (major, minor, micro) = m.groups()
            if int(major) > 1 or int(minor) > 0:
                if int(micro) > 0:
                    # Snap to next major version. Perhaps not
                    # exactly correct, but good for all symbols
                    # we export but nm_ethtool_optname_is_feature().
                    minor = str(int(minor) + 2)
                version = major + "." + minor
            else:
                version = None
        elif (
            line.endswith(";")
            and not line.startswith("}")
            and not line.startswith("#")
            and not line == "*;"
        ):
            c_syms[str_removesuffix(line, ";")] = version

    # These are exceptions and we cannot know the version for the symbol so we
    # hardcode it.
    c_syms["nm_ethtool_optname_is_feature"] = "1.20"
    c_syms["nm_setting_bond_port_get_prio"] = "1.44"
    c_syms["nm_ethtool_optname_is_fec"] = "1.52"
    c_syms["nm_setting_ethtool_fec_mode_get_type"] = "1.52"

    return c_syms


parser = argparse.ArgumentParser()
parser.add_argument(
    "--gir",
    metavar="FILE",
    help="NM-1.0.gir file",
    required=True,
)
parser.add_argument(
    "--ver",
    metavar="FILE",
    help="libnm.ver file",
    required=True,
)

args = parser.parse_args()

gir_syms = syms_from_gir(args.gir)
ver_syms = syms_from_ver(args.ver)

exit_code = 0

for gir_sym, gir_ver in gir_syms.items():
    if gir_sym not in ver_syms:
        exit_code = 1
        print(
            'FAIL: "%s" found in "%s", but is not exported. Needs adding to "%s"?'
            % (gir_sym, args.gir, args.ver),
            file=sys.stderr,
        )
        continue
    if gir_ver != ver_syms[gir_sym]:
        exit_code = 1
        print(
            'FAIL: "%s" exported in version "%s" but documented as available since "%s"'
            % (gir_sym, ver_syms[gir_sym], gir_ver),
            file=sys.stderr,
        )

# In python2, dict.keys() returns lists, not sets. Cast them.
for sym in set(ver_syms.keys()) - set(gir_syms.keys()):
    exit_code = 1
    print(
        'FAIL: "%s" found in "%s", but not in "%s". Maybe the doc comment is wrong or g-ir-scanner messed up?'
        % (sym, args.ver, args.gir),
        file=sys.stderr,
    )

sys.exit(exit_code)
