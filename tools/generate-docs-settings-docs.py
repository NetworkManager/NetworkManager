#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import xml.etree.ElementTree as ET
import argparse
import re

###############################################################################


def strip_new_lines(desc_string):
    desc_string = re.sub(r"\n\s*", r" ", desc_string)
    return desc_string


def escape_quotes(desc_string):
    desc_string = re.sub(r"\"", r"\"", desc_string)
    return desc_string


###############################################################################


def main(output_path_str, xml_path_str):
    xml = ET.parse(xml_path_str).getroot()

    doc = ""
    doc += "/* Generated file. Do not edit. */\n\n"

    for setting in xml:
        name_set_upper = setting.attrib["name_upper"]

        for property in setting:
            name_prop_upper = property.attrib["name_upper"]
            desc_string = ""
            desc = property.find("description")

            if desc is not None:
                desc_string = desc.text

            desc_string = strip_new_lines(desc_string)
            desc_string = escape_quotes(desc_string)
            desc_string = desc_string.lstrip(" ")

            doc += "#define DESCRIBE_DOC_NM_SETTING_"
            doc += name_set_upper
            doc += "_"
            doc += name_prop_upper
            doc += ' N_("'
            doc += desc_string
            doc += '")\n'

    file = open(output_path_str, "w")
    file.write(doc)
    file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="specify output file",
        required=True,
    )
    parser.add_argument(
        "--xml",
        metavar="PATH",
        help="specify input file",
        required=True,
    )

    args = parser.parse_args()
    main(args.output, args.xml)
