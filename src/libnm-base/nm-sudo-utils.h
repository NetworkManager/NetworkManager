/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_SUDO_UTILS_H__
#define __NM_SUDO_UTILS_H__

/*****************************************************************************/

#define NM_SUDO_DBUS_BUS_NAME    "org.freedesktop.nm.sudo"
#define NM_SUDO_DBUS_OBJECT_PATH "/org/freedesktop/nm/sudo"
#define NM_SUDO_DBUS_IFACE_NAME  "org.freedesktop.nm.sudo"

/*****************************************************************************/

#define NM_OVSDB_SOCKET RUNSTATEDIR "/openvswitch/db.sock"

typedef enum {
    NM_SUDO_GET_FD_TYPE_NONE         = 0,
    NM_SUDO_GET_FD_TYPE_OVSDB_SOCKET = 1,
} NMSudoGetFDType;

int nm_sudo_utils_open_fd(NMSudoGetFDType fd_type, GError **error);

#endif /* __NM_SUDO_UTILS_H__ */
