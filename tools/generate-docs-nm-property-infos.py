#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import os, re, sys


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


def scan_doc_comments(plugin, outfile, file, start_tag, end_tag):
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
                write_data(outfile, parsed_data)
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
            parsed_data[keyword] = escape_xml_char(value)
        elif kwd_more_line_found:
            if not keyword:
                print("Extra mess in a comment: %s" % (line))
                exit(1)
            else:
                value = kwd_more_line_found.group(1) + " "
                parsed_data[keyword] += escape_xml_char(value)
    for keyword in keywords:
        if keyword == "variable" and keyword not in parsed_data:
            parsed_data[keyword] = parsed_data["property"]
        elif keyword not in parsed_data:
            parsed_data[keyword] = ""
    for key in parsed_data.keys():
        parsed_data[key] = parsed_data[key].rstrip()
    return parsed_data


def write_data(outfile, parsed_data):
    outfile.write(
        '<property name="{0}" variable="{1}" format="{2}" values="{3}" default="{4}" example="{5}" description="{6}"/>\n'.format(
            parsed_data["property"],
            parsed_data["variable"],
            parsed_data["format"],
            parsed_data["values"],
            parsed_data["default"],
            parsed_data["example"],
            parsed_data["description"],
        )
    )


def escape_xml_char(text):
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&apos;")

    return text


if len(sys.argv) < 4:
    print("Usage: %s [plugin] [output-xml-file] [srcfiles]" % (sys.argv[0]))
    exit(1)

argv = list(sys.argv[1:])
plugin, output, source_files = argv[0], argv[1], argv[2:]
start_tag = "---" + plugin + "---"
end_tag = "---end---"
outfile = open(output, mode="w")

# write XML header
outfile.write("<nm-setting-docs>\n")
outfile.write("  ")

for one_file in source_files:
    setting_name = get_setting_name(one_file)
    if setting_name:
        outfile.write('<setting name="' + setting_name + '">\n')
        scan_doc_comments(plugin, outfile, one_file, start_tag, end_tag)
        outfile.write("</setting>\n")


# write XML footer
outfile.write("</nm-setting-docs>")

# close output file
outfile.close()
