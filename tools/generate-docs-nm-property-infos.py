#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re
import sys
import collections
import xml.etree.ElementTree as ET


enums = {}
enumvals = {}


class LineError(Exception):
    def __init__(self, line_no, msg):
        Exception.__init__(self, msg)
        self.line_no = line_no


_dbg_level = 0
try:
    _dbg_level = int(os.getenv("NM_DEBUG_GENERATE_DOCS", 0))
except Exception:
    pass


def dbg(msg, level=1):
    if level <= _dbg_level:
        print(msg)


def iter_unique(iterable, default=None):
    found = False
    for i in iterable:
        assert not found
        found = True
        i0 = i
    if found:
        return i0
    return default


def xnode_get_or_create(root_node, node_name, name):
    # From root_node, get the node "<{node_name} name={name} .../>"
    # or create one, if it doesn't exist.
    node = iter_unique(
        (node for node in root_node.findall(node_name) if node.attrib["name"] == name)
    )
    if node is None:
        created = True
        node = ET.SubElement(root_node, node_name, name=name)
    else:
        created = False

    return node, created


def init_enumvals(girxml):
    ns_map = {
        "c": "http://www.gtk.org/introspection/c/1.0",
        "gi": "http://www.gtk.org/introspection/core/1.0",
        "glib": "http://www.gtk.org/introspection/glib/1.0",
    }
    type_key = "{%s}type" % ns_map["c"]
    identifier_key = "{%s}identifier" % ns_map["c"]
    nick_key = "{%s}nick" % ns_map["glib"]

    for enum in girxml.findall("./gi:namespace/gi:enumeration", ns_map):
        enum_cname = enum.attrib[type_key]
        enums[enum_cname] = []
        for enumval in enum.findall("./gi:member", ns_map):
            if enumval.find('./gi:attribute[@name="NM.internal"]', ns_map) is not None:
                continue

            cname = enumval.attrib[identifier_key]
            num_val = enumval.attrib["value"]
            doc = enumval.find("./gi:doc", ns_map)
            doc = doc.text if doc is not None else None
            nick = enumval.attrib.get(nick_key)
            nick = "%s (%s)" % (nick, num_val) if nick else None

            enums[enum_cname].append(cname)
            enumvals[cname] = {
                "cvalue": "%s (%s)" % (cname, num_val),
                "nick": nick,
                "doc": doc,
            }

    for enum in girxml.findall("./gi:namespace/gi:bitfield", ns_map):
        enum_cname = enum.attrib[type_key]
        enums[enum_cname] = []
        for enumval in enum.findall("./gi:member", ns_map):
            if enumval.find('./gi:attribute[@name="NM.internal"]', ns_map) is not None:
                continue

            cname = enumval.attrib[identifier_key]
            num_val = int(enumval.attrib["value"])
            doc = enumval.find("./gi:doc", ns_map)
            doc = doc.text if doc is not None else None
            nick = enumval.attrib.get(nick_key)
            nick = "%s (0x%x)" % (nick, num_val) if nick else None

            enums[enum_cname].append(cname)
            enumvals[cname] = {
                "cvalue": "%s (0x%x)" % (cname, num_val),
                "nick": nick,
                "doc": doc,
            }


def get_setting_names(source_file):
    m = re.match(r"^(.*)/libnm-core-impl/(nm-setting-[^/]*)\.c$", source_file)
    assert m

    path_prefix, file_base = (m.group(1), m.group(2))

    if file_base == "nm-setting-ip-config":
        # Special case ip-config, which is a base class.
        return 0, ("ipv4", "ipv6")

    header_file = "%s/libnm-core-public/%s.h" % (path_prefix, file_base)

    try:
        f = open(header_file, "r")
    except OSError:
        raise Exception(
            'Can not open header file "%s" for "%s"' % (header_file, source_file)
        )

    with f:
        for line in f:
            m = re.search(r"^#define +NM_SETTING_.+SETTING_NAME\s+\"(\S+)\"$", line)
            if m:
                return 1, (m.group(1),)

    raise Exception(
        'Can\'t find setting name in header file "%s" for "%s"'
        % (header_file, source_file)
    )


def get_file_infos(source_files):
    # This function parses the source files and detects the
    # used setting name. The returned sections are sorted by setting
    # name.
    #
    # The file "nm-setting-ip-config.c" can contain information
    # for "ipv4" and "ipv6" settings. Thus, to sort the files
    # is a bit more involved.

    # First, get a list of priority and setting-names that belong
    # to the source file. Sort by priority,setting-names. It's
    # important that "nm-setting-ip-config.c" gets parsed before
    # "nm-setting-ip[46]-config.c".
    file_infos = []
    for source_file in source_files:
        priority, setting_names = get_setting_names(source_file)
        file_infos.append((priority, setting_names, source_file))
    file_infos.sort()

    d = {}
    for priority, setting_names, source_file in file_infos:
        for setting_name in setting_names:
            l = d.get(setting_name, None)
            if l is None:
                l = list()
                d[setting_name] = l
            l.append(source_file)
    for key in sorted(d.keys()):
        for f in d[key]:
            yield key, f


KEYWORD_XML_TYPE_NESTED = "nested"
KEYWORD_XML_TYPE_ELEM = "elem"
KEYWORD_XML_TYPE_ATTR = "attr"

keywords = collections.OrderedDict(
    [
        ("property", KEYWORD_XML_TYPE_ATTR),
        ("variable", KEYWORD_XML_TYPE_ATTR),
        ("format", KEYWORD_XML_TYPE_ATTR),
        ("values", KEYWORD_XML_TYPE_ATTR),
        ("default", KEYWORD_XML_TYPE_ATTR),
        ("example", KEYWORD_XML_TYPE_ATTR),
        ("description", KEYWORD_XML_TYPE_ELEM),
        ("description-docbook", KEYWORD_XML_TYPE_NESTED),
    ]
)


def keywords_allowed(tag, keyword):
    # certain keywords might not be valid for some tags.
    # Currently, all of them are always valid.
    assert keyword in keywords
    return True


def write_data(tag, setting_node, line_no, parsed_data):

    for k in parsed_data.keys():
        assert keywords_allowed(tag, k)
        assert k in keywords

    name = parsed_data["property"]
    property_node, created = xnode_get_or_create(setting_node, "property", name)
    if not created:
        raise LineError(line_no, 'Duplicate property <property name="%s"...' % (name,))

    for k, xmltype in keywords.items():
        if k == "property":
            continue

        v = parsed_data.get(k, None)
        if v is None:
            continue

        if xmltype == KEYWORD_XML_TYPE_NESTED:
            # Set as XML nodes. The input data is XML itself.
            des = ET.fromstring("<%s>%s</%s>" % (k, v, k))
            property_node.append(des)
        elif xmltype == KEYWORD_XML_TYPE_ELEM:
            node = ET.SubElement(property_node, k)
            node.text = v
        elif xmltype == KEYWORD_XML_TYPE_ATTR:
            property_node.set(k, v)
        else:
            assert False


def expand_enumval(enumval_name, use_nicks):
    if enumval_name not in enumvals:
        return enumval_name
    enumval = enumvals[enumval_name]
    return enumval["nick"] if use_nicks and enumval["nick"] else enumval["cvalue"]


def expand_all_enumvals(enum, use_nicks):
    assert enum in enums
    return ", ".join(expand_enumval(val_name, use_nicks) for val_name in enums[enum])


def expand_all_enumvals_with_docs(enum, use_nicks):
    assert enum in enums

    out_str = "<itemizedlist>"
    for enumval_name in enums[enum]:
        assert enumval_name in enumvals
        enumval = enumvals[enumval_name]
        out_str += "<listitem><para><literal>%s</literal>%s</para></listitem>" % (
            expand_enumval(enumval_name, use_nicks),
            " - " + enumval["doc"] if enumval["doc"] else "",
        )
    out_str += "</itemizedlist>"

    return out_str


def format_descriptions(tag, parsed_data):
    if (
        parsed_data.get("description", None) is not None
        and parsed_data.get("description-docbook", None) is None
    ):
        # we have a description, but no docbook. Generate one.
        parsed_data["description-docbook"] = ""
        for line in parsed_data["description"].split("\n"):
            para = ET.Element("para")
            para.text = line
            parsed_data["description-docbook"] += ET.tostring(para, encoding='unicode')
    elif (
        parsed_data.get("description-docbook", None) is not None
        and parsed_data.get("description", None) is None
    ):
        raise Exception(
            'Invalid configuration. When specifying "description-docbook:" there MUST be also a  "description:"'
        )
    elif parsed_data.get("description", None) is None:
        return

    # Expand enumvals expressions (%ENUM_VALUE, #EnumName:** and #EnumName:*)
    use_nicks = tag == "nmcli"

    parsed_data["description"] = re.sub(
        r"#([A-Za-z0-9_]*):\*{1,2}",
        lambda match: expand_all_enumvals(match.group(1), use_nicks),
        parsed_data["description"],
    )

    parsed_data["description"] = re.sub(
        r"%([^%]\w*)",
        lambda match: expand_enumval(match.group(1), use_nicks),
        parsed_data["description"],
    )

    parsed_data["description-docbook"] = re.sub(
        r"#([A-Za-z0-9_]*):\*\*",
        lambda match: expand_all_enumvals_with_docs(match.group(1), use_nicks),
        parsed_data["description-docbook"],
    )

    parsed_data["description-docbook"] = re.sub(
        r"#([A-Za-z0-9_]*):\*",
        lambda match: expand_all_enumvals(match.group(1), use_nicks),
        parsed_data["description-docbook"],
    )

    parsed_data["description-docbook"] = re.sub(
        r"%([^%]\w*)",
        lambda match: expand_enumval(match.group(1), use_nicks),
        parsed_data["description-docbook"],
    )


def parse_data(tag, line_no, lines):
    assert lines
    parsed_data = {}
    keyword = ""
    indent = None
    for line in lines:
        assert "\n" not in line
        line_no += 1
        m = re.search(r"^     \*(| .*)$", line)
        if not m:
            raise LineError(line_no, 'Invalid formatted line "%s"' % (line,))
        content = m.group(1)

        m = re.search("^ ([-a-z0-9]+):(.*)$", content)
        text_keyword_started = None
        if m:
            keyword = m.group(1)
            if keyword in parsed_data:
                raise LineError(line_no, 'Duplicated keyword "%s"' % (keyword,))
            text = m.group(2)
            text_keyword_started = text
            if text:
                if text[0] != " " or len(text) == 1:
                    raise LineError(line_no, 'Invalid formatted line "%s"' % (line,))
                text = text[1:]
            if not keywords_allowed(tag, keyword):
                raise LineError(line_no, 'Invalid key "%s" for %s' % (keyword, tag))
            if parsed_data and keyword == "property":
                raise LineError(line_no, 'The "property:" keywork must be first')
            parsed_data[keyword] = text
            indent = None
        else:
            if content == "":
                text = ""
            elif content[0] == " " and len(content) > 1:
                text = content[1:]
                assert text
                if indent is None:
                    indent = re.search("^( *)", text).group(1)
                if not text.startswith(indent):
                    raise LineError(line_no, 'Unexpected indention in "%s"' % (line,))
                text = text[len(indent) :]
            else:
                raise LineError(line_no, 'Unexpected line "%s"' % (line,))
            if not keyword:
                raise LineError(line_no, "Expected data in comment: %s" % (line))
            if text and text[0] == "\\":
                assert False
                text = text[1:]
            if separator == " " and text == "":
                # No separator to add. This is a blank line
                pass
            else:
                parsed_data[keyword] = parsed_data[keyword] + separator + text

        if keywords[keyword] == KEYWORD_XML_TYPE_NESTED:
            # This is plain XML. They lines are joined by newlines.
            separator = "\n"
        elif text_keyword_started == "":
            # If the previous line was just "tag:$", we don't need a separator
            # the next time.
            separator = ""
        elif not text:
            # A blank line is used to mark a line break, while otherwise
            # lines are joined by space.
            separator = "\n"
        else:
            separator = " "
    if "property" not in parsed_data:
        raise LineError(line_no, 'Missing "property:" tag')
    for keyword in keywords.keys():
        if not keywords_allowed(tag, keyword):
            continue
        if keyword not in parsed_data:
            parsed_data[keyword] = None
    return parsed_data


def process_setting(tag, root_node, source_file, setting_name):

    dbg(
        "> > tag:%s, source_file:%s, setting_name:%s" % (tag, source_file, setting_name)
    )

    start_tag = "---" + tag + "---"
    end_tag = "---end---"

    setting_node, created = xnode_get_or_create(root_node, "setting", setting_name)

    try:
        f = open(source_file, "r")
    except OSError:
        raise Exception("Can not open file: %s" % (source_file))

    lines = None
    with f:
        line_no = 0
        just_had_end_tag = False
        line_no_start = None
        for line in f:
            line_no += 1
            if line and line[-1] == "\n":
                line = line[:-1]
            if just_had_end_tag:
                # After the end-tag, we still expect one particular line. Be strict about
                # this.
                just_had_end_tag = False
                if line != "     */":
                    raise LineError(
                        line_no,
                        'Invalid end tag "%s". Expects literally "     */" after end-tag'
                        % (line,),
                    )
            elif start_tag in line:
                if line != "    /* " + start_tag:
                    raise LineError(
                        line_no,
                        'Invalid start tag "%s". Expects literally "    /* %s"'
                        % (line, start_tag),
                    )
                if lines is not None:
                    raise LineError(
                        line_no, 'Invalid start tag "%s", missing end-tag' % (line,)
                    )
                lines = []
                line_no_start = line_no
            elif end_tag in line and lines is not None:
                if line != "     * " + end_tag:
                    raise LineError(line_no, 'Invalid end tag: "%s"' % (line,))
                parsed_data = parse_data(tag, line_no_start, lines)
                if not parsed_data:
                    raise Exception('invalid data: line %s, "%s"' % (line_no, lines))
                format_descriptions(tag, parsed_data)
                dbg("> > > property: %s" % (parsed_data["property"],))
                if _dbg_level > 1:
                    for keyword in sorted(parsed_data.keys()):
                        v = parsed_data[keyword]
                        if v is not None:
                            v = '"%s"' % (v,)
                        dbg(
                            "> > > > [%s] (%s) = %s" % (keyword, keywords[keyword], v),
                            level=2,
                        )
                write_data(tag, setting_node, line_no_start, parsed_data)
                lines = None
            elif lines is not None:
                lines.append(line)
        if lines is not None or just_had_end_tag:
            raise LineError(line_no_start, "Unterminated start tag")


def process_settings_docs(tag, output, gir_file, source_files):

    dbg("> tag:%s, output:%s" % (tag, output))

    root_node = ET.Element("nm-setting-docs")

    init_enumvals(ET.parse(gir_file).getroot())

    for setting_name, source_file in get_file_infos(source_files):
        try:
            process_setting(tag, root_node, source_file, setting_name)
        except LineError as e:
            raise Exception(
                "Error parsing %s, line %s (tag:%s, setting_name:%s): %s"
                % (source_file, e.line_no, tag, setting_name, str(e))
            )
        except Exception as e:
            raise Exception(
                "Error parsing %s (tag:%s, setting_name:%s): %s"
                % (source_file, tag, setting_name, str(e))
            )

    ET.ElementTree(root_node).write(output)


def main():
    if len(sys.argv) < 4:
        print(
            "Usage: %s [tag] [output-xml-file] [gir-file] [srcfiles...]" % (sys.argv[0])
        )
        exit(1)

    process_settings_docs(
        tag=sys.argv[1],
        output=sys.argv[2],
        gir_file=sys.argv[3],
        source_files=sys.argv[4:],
    )


if __name__ == "__main__":
    main()


###############################################################################
# Tests
###############################################################################


def setup_module():
    global pytest
    import pytest


def t_srcdir():
    return os.path.abspath(os.path.dirname(__file__) + "/..")


def t_setting_c(name):
    return t_srcdir() + "/src/libnm-core-impl/nm-setting-" + name + ".c"


def test_file_location():
    assert t_srcdir() + "/tools/generate-docs-nm-property-infos.py" == os.path.abspath(
        __file__
    )
    assert os.path.isfile(t_srcdir() + "/src/libnm-core-impl/nm-setting-connection.c")

    assert os.path.isfile(t_setting_c("ip-config"))


def test_get_setting_names():
    assert (1, ("connection",)) == get_setting_names(
        t_srcdir() + "/src/libnm-core-impl/nm-setting-connection.c"
    )
    assert (1, ("ipv4",)) == get_setting_names(
        t_srcdir() + "/src/libnm-core-impl/nm-setting-ip4-config.c"
    )
    assert (0, ("ipv4", "ipv6")) == get_setting_names(
        t_srcdir() + "/src/libnm-core-impl/nm-setting-ip-config.c"
    )


def test_get_file_infos():

    t = ["connection", "ip-config", "ip4-config", "proxy", "wired"]

    assert [
        (
            "802-3-ethernet",
            t_setting_c("wired"),
        ),
        (
            "connection",
            t_setting_c("connection"),
        ),
        (
            "ipv4",
            t_setting_c("ip-config"),
        ),
        (
            "ipv4",
            t_setting_c("ip4-config"),
        ),
        (
            "ipv6",
            t_setting_c("ip-config"),
        ),
        ("proxy", t_setting_c("proxy")),
    ] == list(get_file_infos([t_setting_c(x) for x in t]))


def test_process_setting():
    root_node = ET.Element("nm-setting-docs")
    process_setting("nmcli", root_node, t_setting_c("connection"), "connection")
