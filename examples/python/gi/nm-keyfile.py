#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import os

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib

###############################################################################


def kf_load_from_file(filename):
    kf = GLib.KeyFile.new()
    kf.load_from_file(filename, GLib.KeyFileFlags.NONE)
    return kf


def kf_to_string(kf):
    d, l = kf.to_data()
    return d


def debug(message):
    if os.getenv("DEBUG") == "1":
        print(">>> %s" % (message))


###############################################################################

filename = sys.argv[1]
base_dir = os.path.dirname(os.path.realpath(filename))

kf = kf_load_from_file(filename)

print('> keyfile "%s":' % (filename))
print(">>\n%s\n<<" % (kf_to_string(kf)))

###############################################################################


def kf_handler_read(keyfile, connection, handler_type, handler_data, user_data):
    kf_handler_read_cnt = globals().get("kf_handler_read_cnt", 0) + 1
    globals()["kf_handler_read_cnt"] = kf_handler_read_cnt

    [kf_group, kf_key, cur_setting, cur_property] = handler_data.get_context()

    debug("kf_handler_read(%s): keyfile=%r" % (kf_handler_read_cnt, keyfile))
    debug("kf_handler_read(%s): connection=%r" % (kf_handler_read_cnt, connection))
    debug("kf_handler_read(%s): handler-type=%r" % (kf_handler_read_cnt, handler_type))
    debug("kf_handler_read(%s): handler-data=%r" % (kf_handler_read_cnt, handler_data))
    debug("kf_handler_read(%s): user-data=%r" % (kf_handler_read_cnt, user_data))
    debug("kf_handler_read(%s): kf-group=%r" % (kf_handler_read_cnt, kf_group))
    debug("kf_handler_read(%s): kf-key=%r" % (kf_handler_read_cnt, kf_key))
    debug("kf_handler_read(%s): kf-setting=%r" % (kf_handler_read_cnt, cur_setting))
    debug("kf_handler_read(%s): kf-property=%r" % (kf_handler_read_cnt, cur_property))

    if handler_type == NM.KeyfileHandlerType.WARN:
        [message, severity] = handler_data.warn_get()
        debug('parse-warning: <%s> = "%s"' % (severity, message))
        print("> warning: %s" % (message))
        return False

    if handler_type == NM.KeyfileHandlerType.WRITE_CERT:
        # just to show how to abort the parsing. This event won't happen
        # for read.
        handler_data.fail_with_error(
            GLib.GError.new_literal(
                NM.ConnectionError.quark(), "hallo1", NM.ConnectionError.MISSINGPROPERTY
            )
        )

    # don't handle unknown handler types.
    return False


try:
    print("parse keyfile...")
    c = NM.keyfile_read(kf, base_dir, NM.KeyfileHandlerFlags.NONE, kf_handler_read, 42)
except Exception as e:
    print("parsing failed: %r" % (e))
    raise

verify_failure = None
try:
    c.verify()
except Exception as e:
    verify_failure = e.message

print(
    'parsing succeeded: "%s" (%s)%s'
    % (
        c.get_id(),
        c.get_uuid(),
        " (invalid: " + verify_failure + ")" if verify_failure is not None else "",
    )
)


###############################################################################


def kf_handler_write(connection, keyfile, handler_type, handler_data, user_data):
    kf_handler_write_cnt = globals().get("kf_handler_write_cnt", 0) + 1
    globals()["kf_handler_write_cnt"] = kf_handler_write_cnt

    [kf_group, kf_key, cur_setting, cur_property] = handler_data.get_context()

    debug("kf_handler_write(%s): keyfile=%r" % (kf_handler_write_cnt, keyfile))
    debug("kf_handler_write(%s): connection=%r" % (kf_handler_write_cnt, connection))
    debug(
        "kf_handler_write(%s): handler-type=%r" % (kf_handler_write_cnt, handler_type)
    )
    debug(
        "kf_handler_write(%s): handler-data=%r" % (kf_handler_write_cnt, handler_data)
    )
    debug("kf_handler_write(%s): user-data=%r" % (kf_handler_write_cnt, user_data))
    debug("kf_handler_write(%s): kf-group=%r" % (kf_handler_write_cnt, kf_group))
    debug("kf_handler_write(%s): kf-key=%r" % (kf_handler_write_cnt, kf_key))
    debug("kf_handler_write(%s): kf-setting=%r" % (kf_handler_write_cnt, cur_setting))
    debug("kf_handler_write(%s): kf-property=%r" % (kf_handler_write_cnt, cur_property))

    if handler_type == NM.KeyfileHandlerType.WRITE_CERT:
        return False
    return False


try:
    print("")
    print("write keyfile...")
    kf2 = NM.keyfile_write(c, NM.KeyfileHandlerFlags.NONE, kf_handler_write, 43)
except Exception as e:
    print("write failed: %r" % (e))
    raise

print("persisted again:")
print(">>\n%s\n<<" % (kf_to_string(kf2)))
