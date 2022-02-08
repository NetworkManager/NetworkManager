/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_PRIV_HELPER_UTILS_H__
#define __NM_PRIV_HELPER_UTILS_H__

/*****************************************************************************/

#define NM_PRIV_HELPER_DBUS_BUS_NAME    "org.freedesktop.nm_priv_helper"
#define NM_PRIV_HELPER_DBUS_OBJECT_PATH "/org/freedesktop/nm_priv_helper"
#define NM_PRIV_HELPER_DBUS_IFACE_NAME  "org.freedesktop.nm_priv_helper"

/*****************************************************************************/

#define NM_OVSDB_SOCKET RUNSTATEDIR "/openvswitch/db.sock"

typedef enum {
    NM_PRIV_HELPER_GET_FD_TYPE_NONE         = 0,
    NM_PRIV_HELPER_GET_FD_TYPE_OVSDB_SOCKET = 1,
} NMPrivHelperGetFDType;

int nm_priv_helper_utils_open_fd(NMPrivHelperGetFDType fd_type, GError **error);

#endif /* __NM_PRIV_HELPER_UTILS_H__ */
