#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright (C) 2009 - 2017 Red Hat, Inc.
#
from __future__ import print_function, unicode_literals
import xml.etree.ElementTree as ET
import argparse
import os
import gi
import re

gi.require_version("GIRepository", "2.0")
from gi.repository import GIRepository

try:
    libs = os.environ["LD_LIBRARY_PATH"].split(":")
    libs.reverse()
    for lib in libs:
        GIRepository.Repository.prepend_library_path(lib)
except AttributeError:
    # An old GI version, that has no prepend_library_path
    # It's alright, it probably interprets LD_LIBRARY_PATH
    # correctly.
    pass
except KeyError:
    pass

gi.require_version("NM", "1.0")
from gi.repository import NM, GObject

dbus_type_name_map = {
    "b": "boolean",
    "s": "string",
    "i": "int32",
    "u": "uint32",
    "t": "uint64",
    "x": "int64",
    "y": "byte",
    "as": "array of string",
    "au": "array of uint32",
    "ay": "byte array",
    "a{ss}": "dict of string to string",
    "a{sv}": "vardict",
    "aa{sv}": "array of vardict",
    "aau": "array of array of uint32",
    "aay": "array of byte array",
    "a(ayuay)": "array of legacy IPv6 address struct",
    "a(ayuayu)": "array of legacy IPv6 route struct",
}

ns_map = {
    "c": "http://www.gtk.org/introspection/c/1.0",
    "gi": "http://www.gtk.org/introspection/core/1.0",
    "glib": "http://www.gtk.org/introspection/glib/1.0",
}
identifier_key = "{%s}identifier" % ns_map["c"]
nick_key = "{%s}nick" % ns_map["glib"]
symbol_prefix_key = "{%s}symbol-prefix" % ns_map["c"]

constants = {
    "TRUE": "TRUE",
    "FALSE": "FALSE",
    "G_MAXUINT32": "G_MAXUINT32",
    "NULL": "NULL",
}
setting_names = {}


def get_setting_name_define(setting):
    n = setting.attrib[symbol_prefix_key]
    if n and n.startswith("setting_"):
        return n[8:].upper()
    raise Exception('Unexpected symbol_prefix_key "%s"' % (n))


def init_constants(girxml, settings):
    for const in girxml.findall("./gi:namespace/gi:constant", ns_map):
        cname = const.attrib["{%s}type" % ns_map["c"]]
        cvalue = const.attrib["value"]
        if const.find('./gi:type[@name="utf8"]', ns_map) is not None:
            cvalue = '"%s"' % cvalue
        constants[cname] = cvalue

    for enum in girxml.findall("./gi:namespace/gi:enumeration", ns_map):
        for enumval in enum.findall("./gi:member", ns_map):
            cname = enumval.attrib[identifier_key]
            cvalue = "%s (%s)" % (cname, enumval.attrib["value"])
            constants[cname] = cvalue

    for enum in girxml.findall("./gi:namespace/gi:bitfield", ns_map):
        for enumval in enum.findall("./gi:member", ns_map):
            cname = enumval.attrib[identifier_key]
            cvalue = "%s (0x%x)" % (cname, int(enumval.attrib["value"]))
            constants[cname] = cvalue

    for setting in settings:
        setting_type_name = "NM" + setting.attrib["name"]
        setting_name_symbol = (
            "NM_SETTING_" + get_setting_name_define(setting) + "_SETTING_NAME"
        )
        if setting_name_symbol in constants:
            setting_name = constants[setting_name_symbol]
            setting_names[setting_type_name] = setting_name


def get_prop_type(setting, pspec):
    dbus_type = setting.get_dbus_property_type(pspec.name).dup_string()
    prop_type = dbus_type_name_map[dbus_type]

    if GObject.type_is_a(pspec.value_type, GObject.TYPE_ENUM) or GObject.type_is_a(
        pspec.value_type, GObject.TYPE_FLAGS
    ):
        prop_type = "%s (%s)" % (pspec.value_type.name, prop_type)

    return prop_type


def remove_prefix(line, prefix):
    return line[len(prefix) :] if line.startswith(prefix) else line


def format_docs(doc_xml):
    doc = doc_xml.text

    # split docs into lines
    lines = re.split("\n", doc)
    # strip leading *char and strip white spaces
    lines = [remove_prefix(l, "*").strip() for l in lines]
    doc = ""
    for l in lines:
        if l:
            doc += l + " "
        else:
            doc = doc.strip(" ") + "\n\n"

    doc = doc.strip("\n ")

    # Expand constants
    doc = re.sub(r"%([^%]\w*)", lambda match: constants[match.group(1)], doc)

    # #NMSettingWired:mac-address -> "mac-address"
    doc = re.sub(r"#[A-Za-z0-9_]*:([A-Za-z0-9_-]*)", r'"\1"', doc)

    # #NMSettingWired setting -> "802-3-ethernet" setting
    doc = re.sub(
        r"#([A-Z]\w*) setting",
        lambda match: setting_names[match.group(1)] + " setting",
        doc,
    )

    # remaining gtk-doc cleanup
    doc = doc.replace("%%", "%")
    doc = doc.replace("<!-- -->", "")
    doc = re.sub(r" Element-.ype:.*", "", doc)
    doc = re.sub(r"#([A-Z]\w*)", r"\1", doc)

    # Remove sentences that refer to functions
    if "FindProxyForURL()" in doc:
        # FIXME: this would break the description for "proxy.pac-script"
        # Work around. But really the entire approach here is flawed
        # and needs improvement.
        pass
    else:
        doc = re.sub(r"\.\s+[^.]*\w\(\)[^.]*\.", r".", doc)

    return doc


def get_docs(propxml):
    doc_xml = propxml.find("gi:doc", ns_map)
    if doc_xml is None:
        return None
    else:
        return format_docs(doc_xml)


def get_default_value(setting, pspec, propxml):
    default_value = setting.get_property(pspec.name.replace("-", "_"))
    if default_value is None:
        return default_value

    value_type = get_prop_type(setting, pspec)
    if value_type == "string" and default_value != "" and pspec.name != "name":
        default_value = '"%s"' % default_value
    elif value_type == "boolean":
        default_value = str(default_value).upper()
    elif value_type == "byte array":
        default_value = "[]"
    elif str(default_value).startswith("<"):
        default_value = None
    elif str(default_value).startswith("["):
        default_value = None

    return default_value


def settings_sort_key(x):
    x_prefix = x.attrib["{%s}symbol-prefix" % ns_map["c"]]
    # always sort NMSettingConnection first
    return (x_prefix != "setting_connection", x_prefix)


def create_desc_docbook(desc_docbook, description):
    lines = re.split("\n", description)

    paragraph = ET.SubElement(
        desc_docbook,
        "para",
    )

    for l in lines:
        if not l:
            # A blank line. This starts a new paragraph
            paragraph = ET.SubElement(desc_docbook, "para")
            continue
        paragraph.text = l


def main(gir_path_str, output_path_str):
    girxml = ET.parse(gir_path_str).getroot()

    basexml = girxml.find('./gi:namespace/gi:class[@name="Setting"]', ns_map)
    settings = girxml.findall('./gi:namespace/gi:class[@parent="Setting"]', ns_map)
    # Hack. Need a better way to do this
    ipxml = girxml.find('./gi:namespace/gi:class[@name="SettingIPConfig"]', ns_map)
    settings.extend(
        girxml.findall('./gi:namespace/gi:class[@parent="SettingIPConfig"]', ns_map)
    )
    settings = sorted(settings, key=settings_sort_key)

    init_constants(girxml, settings)

    nm_settings_docs_element = ET.Element("nm-setting-docs")
    docs_gir = ET.ElementTree(nm_settings_docs_element)

    for settingxml in settings:
        if "abstract" in settingxml.attrib:
            continue

        new_func = NM.__getattr__(settingxml.attrib["name"])
        setting = new_func()

        class_desc = get_docs(settingxml)
        if class_desc is None:
            raise Exception(
                "%s needs a gtk-doc block with one-line description"
                % setting.props.name
            )
        setting_element = ET.SubElement(
            nm_settings_docs_element,
            "setting",
            attrib={
                "name": setting.props.name,
                "description": class_desc,
                "name_upper": get_setting_name_define(settingxml),
            },
        )

        setting_properties = {
            prop.name: prop
            for prop in GObject.list_properties(setting)
            if prop.name != "name"
        }

        for prop in sorted(setting_properties):
            pspec = setting_properties[prop]

            propxml = settingxml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)
            if propxml is None:
                propxml = basexml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)
            if propxml is None:
                propxml = ipxml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)

            value_type = get_prop_type(setting, pspec)
            value_desc = get_docs(propxml)
            default_value = get_default_value(setting, pspec, propxml)

            if "deprecated" in propxml.attrib:
                deprecated = True
                deprecated_since = propxml.attrib["deprecated-version"]
                deprecated_desc = format_docs(propxml.find("gi:doc-deprecated", ns_map))
            else:
                deprecated = False

            prop_upper = prop.upper().replace("-", "_")

            if value_desc is None:
                raise Exception(
                    "%s.%s needs a documentation description"
                    % (setting.props.name, prop)
                )

            property_attributes = {
                "name": prop,
                "name_upper": prop_upper,
                "type": value_type,
            }

            if default_value is not None:
                property_attributes["default"] = str(default_value)

            property_element = ET.SubElement(
                setting_element,
                "property",
                attrib=property_attributes,
            )

            ET.SubElement(
                property_element,
                "description",
            ).text = value_desc

            if value_desc:
                description_docbook = ET.SubElement(
                    property_element,
                    "description-docbook",
                )

                create_desc_docbook(description_docbook, value_desc)

            if deprecated:
                ET.SubElement(
                    property_element,
                    "deprecated",
                    attrib={
                        "since": deprecated_since,
                    },
                ).text = deprecated_desc

                # The text should only be one line. Otherwise, our simple "<deprecated>" element
                # cannot be rendered nicely.
                assert re.split("\n", deprecated_desc) == [deprecated_desc]

    docs_gir.write(
        output_path_str,
        xml_declaration=True,
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l",
        "--lib-path",
        metavar="PATH",
        action="append",
        help="path to scan for shared libraries",
    )
    parser.add_argument(
        "-g",
        "--gir",
        metavar="FILE",
        help="NM-1.0.gir file",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="output file",
        required=True,
    )

    args = parser.parse_args()

    if args.lib_path:
        for lib in args.lib_path:
            GIRepository.Repository.prepend_library_path(lib)

    main(args.gir, args.output)
