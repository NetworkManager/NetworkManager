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

from gi.repository import NetworkManager, GObject
import argparse, datetime, re, sys
import xml.etree.ElementTree as ET

type_name_map = {
    'gchararray': 'string',
    'GSList_gchararray_': 'array of string',
    'GArray_guchar_': 'byte array',
    'gboolean': 'boolean',
    'guint64': 'uint64',
    'gint': 'int32',
    'guint': 'uint32',
    'GArray_guint_': 'array of uint32',
    'GPtrArray_GArray_guint__': 'array of array of uint32',
    'GPtrArray_GArray_guchar__': 'array of byte array',
    'GPtrArray_gchararray_': 'array of string',
    'GHashTable_gchararray+gchararray_': 'dict of (string::string)',
    'GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar___': 'array of (byte array, uint32, byte array)',
    'GPtrArray_GValueArray_GArray_guchar_+guint+GArray_guchar_+guint__': 'array of (byte array, uint32, byte array, uint32)'
}

ns_map = {
    'c':    'http://www.gtk.org/introspection/c/1.0',
    'gi':   'http://www.gtk.org/introspection/core/1.0',
    'glib': 'http://www.gtk.org/introspection/glib/1.0'
}
identifier_key = '{%s}identifier' % ns_map['c']
nick_key = '{%s}nick' % ns_map['glib']
symbol_prefix_key = '{%s}symbol-prefix' % ns_map['c']

constants = { 'TRUE': 'TRUE', 'FALSE': 'FALSE', 'NULL': 'NULL' }
setting_names = {}

def init_constants(girxml):
    for const in girxml.findall('./gi:namespace/gi:constant', ns_map):
        cname = const.attrib['{%s}type' % ns_map['c']]
        cvalue = const.attrib['value']
        if const.find('./gi:type[@name="utf8"]', ns_map) is not None:
            cvalue = '"%s"' % cvalue
        constants[cname] = cvalue

    for enum in girxml.findall('./gi:namespace/gi:enumeration', ns_map):
        flag = enum.attrib['name'].endswith('Flags')
        for enumval in enum.findall('./gi:member', ns_map):
            cname = enumval.attrib[identifier_key]
            cvalue = enumval.attrib['value']
            if flag:
                cvalue = '%s (0x%x)' % (cname, int(cvalue))
            else:
                cvalue = '%s (%s)' % (cname, cvalue)
            constants[cname] = cvalue

    for setting in girxml.findall('./gi:namespace/gi:class[@parent="Setting"]', ns_map):
        setting_type_name = 'NM' + setting.attrib['name'];
        symbol_prefix = setting.attrib[symbol_prefix_key]
        setting_name = constants['NM_' + symbol_prefix.upper() + '_SETTING_NAME']
        setting_names[setting_type_name] = setting_name

def get_prop_type(setting, pspec, propxml):
    prop_type = pspec.value_type.name
    if type_name_map.has_key(prop_type):
        prop_type = type_name_map[prop_type]
    if prop_type is None:
        prop_type = ''
    return prop_type

def get_docs(setting, pspec, propxml):
    doc_xml = propxml.find('gi:doc', ns_map)
    if doc_xml is None:
        return None

    doc = doc_xml.text
    if propxml.attrib.has_key('deprecated'):
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
    print "Usage: %s --gir FILE --output FILE" % sys.argv[0]
    exit()

parser = argparse.ArgumentParser()
parser.add_argument('-g', '--gir', metavar='FILE', help='NetworkManager-1.0.gir file')
parser.add_argument('-o', '--output', metavar='FILE', help='output file')

args = parser.parse_args()
if args.gir is None or args.output is None:
    usage()

NetworkManager.utils_init()

girxml = ET.parse(args.gir).getroot()
outfile = open(args.output, mode='w')

init_constants(girxml)

basexml = girxml.find('./gi:namespace/gi:class[@name="Setting"]', ns_map)
settings = girxml.findall('./gi:namespace/gi:class[@parent="Setting"]', ns_map)
settings = sorted(settings, key=lambda setting: setting.attrib['{%s}symbol-prefix' % ns_map['c']])

outfile.write("""<?xml version=\"1.0\"?>
<!DOCTYPE nm-setting-docs [
<!ENTITY quot "&#34;">
]>
<nm-setting-docs>
""")

for settingxml in settings:
    new_func = NetworkManager.__getattr__(settingxml.attrib['name'])
    setting = new_func()

    outfile.write("  <setting name=\"%s\">\n" % setting.props.name)

    properties = sorted(GObject.list_properties(setting), key=lambda prop: prop.name)
    for pspec in properties:
        propxml = settingxml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)
        if propxml is None:
            propxml = basexml.find('./gi:property[@name="%s"]' % pspec.name, ns_map)

        value_type = get_prop_type(setting, pspec, propxml)
        value_desc = get_docs(setting, pspec, propxml)
        default_value = get_default_value(setting, pspec, propxml)

        if default_value is not None:
            outfile.write("    <property name=\"%s\" type=\"%s\" default=\"%s\" description=\"%s\" />\n" %
                          (pspec.name, value_type, escape(default_value), escape(value_desc)))
        else:
            outfile.write("    <property name=\"%s\" type=\"%s\" description=\"%s\" />\n" %
                          (pspec.name, value_type, escape(value_desc)))

    outfile.write("  </setting>\n")

outfile.write("</nm-setting-docs>\n")
outfile.close()
