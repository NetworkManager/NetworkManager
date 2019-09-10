// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#ifndef __NM_DISPACHER_API_H__
#define __NM_DISPACHER_API_H__

#define NM_DISPATCHER_DBUS_SERVICE   "org.freedesktop.nm_dispatcher"
#define NM_DISPATCHER_DBUS_INTERFACE "org.freedesktop.nm_dispatcher"
#define NM_DISPATCHER_DBUS_PATH      "/org/freedesktop/nm_dispatcher"

#define NMD_CONNECTION_PROPS_PATH         "path"
#define NMD_CONNECTION_PROPS_FILENAME     "filename"
#define NMD_CONNECTION_PROPS_EXTERNAL     "external"

#define NMD_DEVICE_PROPS_INTERFACE        "interface"
#define NMD_DEVICE_PROPS_IP_INTERFACE     "ip-interface"
#define NMD_DEVICE_PROPS_TYPE             "type"
#define NMD_DEVICE_PROPS_STATE            "state"
#define NMD_DEVICE_PROPS_PATH             "path"

/* Actions */
#define NMD_ACTION_HOSTNAME     "hostname"
#define NMD_ACTION_PRE_UP       "pre-up"
#define NMD_ACTION_UP           "up"
#define NMD_ACTION_PRE_DOWN     "pre-down"
#define NMD_ACTION_DOWN         "down"
#define NMD_ACTION_VPN_PRE_UP   "vpn-pre-up"
#define NMD_ACTION_VPN_UP       "vpn-up"
#define NMD_ACTION_VPN_PRE_DOWN "vpn-pre-down"
#define NMD_ACTION_VPN_DOWN     "vpn-down"
#define NMD_ACTION_DHCP4_CHANGE "dhcp4-change"
#define NMD_ACTION_DHCP6_CHANGE "dhcp6-change"
#define NMD_ACTION_CONNECTIVITY_CHANGE "connectivity-change"

typedef enum {
	DISPATCH_RESULT_UNKNOWN = 0,
	DISPATCH_RESULT_SUCCESS = 1,
	DISPATCH_RESULT_EXEC_FAILED = 2,
	DISPATCH_RESULT_FAILED = 3,
	DISPATCH_RESULT_TIMEOUT = 4,
} DispatchResult;

#endif /* __NM_DISPACHER_API_H__ */
