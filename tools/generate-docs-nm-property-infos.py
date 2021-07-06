#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import sys
import xml.etree.ElementTree as ET


def get_setting_name(one_file):
    setting_name = ""
    assert re.match(r".*/libnm-core-impl/nm-setting-.*\.c$", one_file)
    header_path = one_file.replace("libnm-core-impl", "libnm-core-public")
    header_path = header_path.replace(".c", ".h")
    try:
        header_reader = open(header_path, "r")
    except OSError:
        print("Can not open header file: %s" % (header_path))
        exit(1)

    line = header_reader.readline()
    while line != "":
        setting_name_found = re.search(r"NM_SETTING_.+SETTING_NAME\s+\"(\S+)\"", line)
        if setting_name_found:
            setting_name = setting_name_found.group(1)
            break
        line = header_reader.readline()
    header_reader.close()
    return setting_name


def scan_doc_comments(plugin, setting_node, file, start_tag, end_tag):
    data = []
    push_flag = 0
    try:
        file_reader = open(file, "r")
    except OSError:
        print("Can not open file: %s" % (file))
        exit(1)

    line = file_reader.readline()
    while line != "":
        if start_tag in line:
            push_flag = 1
        elif end_tag in line and push_flag == 1:
            push_flag = 0
            parsed_data = process_data(data)
            if parsed_data:
                write_data(setting_node, parsed_data)
            data = []
        elif push_flag == 1:
            data.append(line)
        line = file_reader.readline()
    file_reader.close()
    return


def process_data(data):
    parsed_data = {}
    if not data:
        return parsed_data
    keywords = [
        "property",
        "variable",
        "format",
        "values",
        "default",
        "example",
        "description",
    ]
    kwd_pat = "|".join(keywords)
    keyword = ""
    for line in data:
        kwd_first_line_found = re.search(
            r"^\s*\**\s+({}):\s+(.*?)\s*$".format(kwd_pat), line
        )
        kwd_more_line_found = re.search(r"^\s*\**\s+(.*?)\s*$", line)
        if kwd_first_line_found:
            keyword = kwd_first_line_found.group(1)
            value = kwd_first_line_found.group(2) + " "
            parsed_data[keyword] = value
        elif kwd_more_line_found:
            if not keyword:
                print("Extra mess in a comment: %s" % (line))
                exit(1)
            else:
                value = kwd_more_line_found.group(1) + " "
                parsed_data[keyword] += value
    for keyword in keywords:
        if keyword == "variable" and keyword not in parsed_data:
            parsed_data[keyword] = parsed_data["property"]
        elif keyword not in parsed_data:
            parsed_data[keyword] = ""
    for key in parsed_data.keys():
        parsed_data[key] = parsed_data[key].rstrip()
    return parsed_data


def write_data(setting_node, parsed_data):
    property_node = ET.SubElement(setting_node, "property")
    property_node.set("name", parsed_data["property"])
    property_node.set("variable", parsed_data["variable"])
    property_node.set("format", parsed_data["format"])
    property_node.set("values", parsed_data["values"])
    property_node.set("default", parsed_data["default"])
    property_node.set("example", parsed_data["example"])
    property_node.set("description", parsed_data["description"])


def pretty_xml(element, newline, level=0):
    if element:
        if (element.text is None) or element.text.isspace():
            element.text = newline
        else:
            element.text = newline + element.text.strip() + newline
    temp = list(element)
    for subelement in temp:
        subelement.tail = newline
        pretty_xml(subelement, newline, level=level + 1)


if len(sys.argv) < 4:
    print("Usage: %s [plugin] [output-xml-file] [srcfiles]" % (sys.argv[0]))
    exit(1)

argv = list(sys.argv[1:])
plugin, output, source_files = argv[0], argv[1], argv[2:]
start_tag = "---" + plugin + "---"
end_tag = "---end---"
root_node = ET.Element("nm-setting-docs")

for one_file in source_files:
    setting_name = get_setting_name(one_file)
    if setting_name:
        setting_node = ET.SubElement(root_node, "setting", name=setting_name)
        setting_node.text = "\n"
        scan_doc_comments(plugin, setting_node, one_file, start_tag, end_tag)

pretty_xml(root_node, "\n")

ET.ElementTree(root_node).write(output)
