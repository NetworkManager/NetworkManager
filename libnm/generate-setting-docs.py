#!/usr/bin/env python
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301 USA.
#
# Copyright 2009 - 2014 Red Hat, Inc.

from __future__ import print_function

import gi
gi.require_version('NM', '1.0')
from gi.repository import NM, GObject
import argparse, datetime, re, sys
import xml.etree.ElementTree as ET

dbus_type_name_map = {
    'b': 'boolean',
    's': 'string',
    'i': 'int32',
    'u': 'uint32',
    't': 'uint64',
    'x': 'int64',
    'y': 'byte',
    'as': 'array of string',
    'au': 'array of uint32',
    'ay': 'byte array',
    'a{ss}': 'dict of string to string',
    'a{sv}': 'vardict',
    'aau': 'array of array of uint32',
    'aay': 'array of byte array',
    'a(ayuay)': 'array of legacy IPv6 address struct',
    'a(ayuayu)': 'array of legacy IPv6 route struct',
}

ns_map = {
    'c':    'http://www.gtk.org/introspection/c/1.0',
    'gi':   'http://www.gtk.org/introspection/core/1.0',
    'glib': 'http://www.gtk.org/introspection/glib/1.0'
}
identifier_key = '{%s}identifier' % ns_map['c']
nick_key = '{%s}nick' % ns_map['glib']
symbol_prefix_key = '{%s}symbol-prefix' % ns_map['c']

constants = {
    'TRUE': 'TRUE',
    'FALSE': 'FALSE',
    'G_MAXUINT32': 'G_MAXUINT32',
    'NULL': 'NULL' }
setting_names = {}

def init_constants(girxml, settings):
    for const in girxml.findall('./gi:namespace/gi:constant', ns_map):
        cname = const.attrib['{%s}type' % ns_map['c']]
        cvalue = const.attrib['value']
        if const.find('./gi:type[@name="utf8"]', ns_map) is not None:
            cvalue = '"%s"' % cvalue
        constants[cname] = cvalue

    for enum in girxml.findall('./gi:namespace/gi:enumeration', ns_map):
        for enumval in enum.findall('./gi:member', ns_map):
            cname = enumval.attrib[identifier_key]
            cvalue = '%s (%s)' % (cname, enumval.attrib['value'])
            constants[cname] = cvalue

    for enum in girxml.findall('./gi:namespace/gi:bitfield', ns_map):
        for enumval in enum.findall('./gi:member', ns_map):
            cname = enumval.attrib[identifier_key]
            cvalue = '%s (0x%x)' % (cname, int(enumval.attrib['value']))
            constants[cname] = cvalue

    for setting in settings:
        setting_type_name = 'NM' + setting.attrib['name'];
        setting_name_symbol = 'NM_' + setting.attrib[symbol_prefix_key].upper() + '_SETTING_NAME'
        if constants.has_key(setting_name_symbol):
            setting_name = constants[setting_name_symbol]
            setting_names[setting_type_name] = setting_name

def get_prop_type(setting, pspec, propxml):
    dbus_type = setting.get_dbus_property_type(pspec.name).dup_string()
    prop_type = dbus_type_name_map[dbus_type]

    if GObject.type_is_a(pspec.value_type, GObject.TYPE_ENUM) or GObject.type_is_a(pspec.value_type, GObject.TYPE_FLAGS):
        prop_type = "%s (%s)" % (pspec.value_type.name, prop_type)

    return prop_type

def get_docs(setting, pspec, propxml):
    doc_xml = propxml.find('gi:doc', ns_map)
    if doc_xml is None:
        return None

    doc = doc_xml.text
    if 'deprecated' in propxml.attrib:
        doc = doc + ' Deprecated: ' + propxml.attrib['deprecated']

    doc = re.sub(r'\n\s*', r' ', doc)

    # Expand constants
    doc = re.sub(r'%([^%]\w*)', lambda match: constants[match.group(1)], doc)

    # #NMSettingWired:mac-address -> "mac-address"
    doc = re.sub(r'#[A-Za-z0-9_]*:([A-Za-z0-9_-]*)', r'"\1"', doc)

    # #NMSettingWired setting -> "802-3-ethernet" setting
    doc = re.sub(r'#([A-Z]\w*) setting', lambda match: setting_names[match.group(1)] + ' setting', doc)

    # remaining gtk-doc cleanup
    doc = doc.replace('%%', '%')
    doc = doc.replace('<!-- -->', '')
    doc = re.sub(r' Element-.ype:.*', '', doc)
    doc = re.sub(r'#([A-Z]\w*)', r'\1', doc)

    # Remove sentences that refer to functions
    doc = re.sub(r'\.\s+[^.]*\w\(\)[^.]*\.', r'.', doc)

    return doc

def get_default_value(setting, pspec, propxml):
    default_value = setting.get_property(pspec.name.replace('-', '_'))
    if default_value is None:
        return default_value

    value_type = get_prop_type(setting, pspec, propxml)
    if value_type == 'string' and default_value != '' and pspec.name != 'name':
        default_value = '"%s"' % default_value
    elif value_type == 'gchar' and default_value != '':
        default_value = "'%s'" % default_value
    elif value_type == 'boolean':
        default_value = str(default_value).upper()
    elif value_type == 'byte array':
        default_value = '[]'
    elif str(default_value).startswith('<'):
        default_value = None

    return default_value

def escape(val):
    return str(val).replace('"', '&quot;')

def usage():
    print("Usage: %s --gir FILE --output FILE" % sys.argv[0])
    exit()

parser = argparse.ArgumentParser()
parser.add_argument('-g', '--gir', metavar='FILE', help='NM-1.0.gir file')
parser.add_argument('-x', '--overrides', metavar='FILE', help='documentation overrides file')
parser.add_argument('-o', '--output', metavar='FILE', help='output file')

args = parser.parse_args()
if args.gir is None or args.output is None:
    usage()

girxml = ET.parse(args.gir).getroot()
outfile = open(args.output, mode='w')

basexml = girxml.find('./gi:namespace/gi:class[@name="Setting"]', ns_map)
settings = girxml.findall('./gi:namespace/gi:class[@parent="Setting"]', ns_map)
# Hack. Need a better way to do this
ipxml = girxml.find('./gi:namespace/gi:class[@name="SettingIPConfig"]', ns_map)
settings.extend(girxml.findall('./gi:namespace/gi:class[@parent="SettingIPConfig"]', ns_map))
settings = sorted(settings, key=lambda setting: setting.attrib['{%s}symbol-prefix' % ns_map['c']])

init_constants(girxml, settings)

if args.overrides is not None:
    overrides = ET.parse(args.overrides).getroot()

outfile.write("""<?xml version=\"1.0\"?>
<!DOCTYPE nm-setting-docs [
<!ENTITY quot "&#34;">
]>
<nm-setting-docs>
""")

for settingxml in settings:
    if settingxml.attrib.has_key('abstract'):
        continue

    new_func = NM.__getattr__(settingxml.attrib['name'])
    setting = new_func()

    outfile.write("  <setting name=\"%s\">\n" % setting.props.name)

    setting_properties = { prop.name: prop for prop in GObject.list_properties(setting) }
    if args.overrides is None:
        setting_overrides = {}
    else:
        setting_overrides = { override.attrib['name']: override for override in overrides.findall('./setting[@name="%s"]/property' % setting.props.name) }

    properties = sorted(set.union(set(setting_properties.keys()), set(setting_overrides.keys())))

    for prop in properties:
        value_type = None
        value_desc = None
        default_value = None

        if prop in setting_properties:
            pspec = setting_properties[prop]
            propxml = settingxml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)
            if propxml is None:
                propxml = basexml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)
            if propxml is None:
                propxml = ipxml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)

            value_type = get_prop_type(setting, pspec, propxml)
            value_desc = get_docs(setting, pspec, propxml)
            default_value = get_default_value(setting, pspec, propxml)

        if prop in setting_overrides:
            override = setting_overrides[prop]
            if override.attrib['format'] != '':
                value_type = override.attrib['format']
            if override.attrib['description'] != '':
                value_desc = override.attrib['description']

        if default_value is not None:
            outfile.write("    <property name=\"%s\" type=\"%s\" default=\"%s\" description=\"%s\" />\n" %
                          (prop, value_type, escape(default_value), escape(value_desc)))
        else:
            outfile.write("    <property name=\"%s\" type=\"%s\" description=\"%s\" />\n" %
                          (prop, value_type, escape(value_desc)))

    outfile.write("  </setting>\n")

outfile.write("</nm-setting-docs>\n")
outfile.close()
