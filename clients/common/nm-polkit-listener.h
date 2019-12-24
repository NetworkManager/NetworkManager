// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_POLKIT_LISTENER_H__
#define __NM_POLKIT_LISTENER_H__

#define NM_TYPE_POLKIT_LISTENER            (nm_polkit_listener_get_type ())
G_DECLARE_FINAL_TYPE (NMPolkitListener, nm_polkit_listener, NM, POLKIT_LISTENER, GObject)

NMPolkitListener *nm_polkit_listener_new (GDBusConnection *dbus_connection, gboolean session_agent);

/* Signals */
#define NM_POLKIT_LISTENER_SIGNAL_REGISTERED      "registered"
#define NM_POLKIT_LISTENER_SIGNAL_REQUEST         "secret-request"
#define NM_POLKIT_LISTENER_SIGNAL_AUTH_SUCCESS    "auth-success"
#define NM_POLKIT_LISTENER_SIGNAL_AUTH_FAILURE    "auth-failure"
#define NM_POLKIT_LISTENER_SIGNAL_ERROR           "error"

#endif /* __NM_POLKIT_LISTENER_H__ */
