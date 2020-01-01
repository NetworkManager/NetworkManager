// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_DBUS_COMPAT_H__
#define __NM_DBUS_COMPAT_H__

#define DBUS_SERVICE_DBUS             "org.freedesktop.DBus"

#define DBUS_PATH_DBUS                "/org/freedesktop/DBus"

#define DBUS_INTERFACE_DBUS           "org.freedesktop.DBus"
#define DBUS_INTERFACE_INTROSPECTABLE "org.freedesktop.DBus.Introspectable"
#define DBUS_INTERFACE_OBJECT_MANAGER "org.freedesktop.DBus.ObjectManager"
#define DBUS_INTERFACE_PEER           "org.freedesktop.DBus.Peer"
#define DBUS_INTERFACE_PROPERTIES     "org.freedesktop.DBus.Properties"

#define DBUS_NAME_FLAG_ALLOW_REPLACEMENT 0x1
#define DBUS_NAME_FLAG_REPLACE_EXISTING  0x2
#define DBUS_NAME_FLAG_DO_NOT_QUEUE      0x4

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER  1
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE       2
#define DBUS_REQUEST_NAME_REPLY_EXISTS         3
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER  4

#endif  /* __NM_DBUS_COMPAT_H__ */
