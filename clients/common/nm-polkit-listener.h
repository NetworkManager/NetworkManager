// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_POLKIT_LISTENER_H__
#define __NM_POLKIT_LISTENER_H__

#define NM_POLKIT_LISTENER_SIGNAL_REGISTERED      "registered"
#define NM_POLKIT_LISTENER_SIGNAL_REQUEST_SYNC    "request-sync"
#define NM_POLKIT_LISTENER_SIGNAL_AUTH_SUCCESS    "auth-success"
#define NM_POLKIT_LISTENER_SIGNAL_AUTH_FAILURE    "auth-failure"
#define NM_POLKIT_LISTENER_SIGNAL_ERROR           "error"

typedef struct _NMPolkitListener NMPolkitListener;
typedef struct _NMPolkitListenerClass NMPolkitListenerClass;

#define NM_TYPE_POLKIT_LISTENER            (nm_polkit_listener_get_type ())
#define NM_POLKIT_LISTENER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_POLKIT_LISTENER, NMPolkitListener))
#define NM_POLKIT_LISTENER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_POLKIT_LISTENER, NMPolkitListenerClass))
#define NM_IS_POLKIT_LISTENER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_POLKIT_LISTENER))
#define NM_IS_POLKIT_LISTENER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_POLKIT_LISTENER))
#define NM_POLKIT_LISTENER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_POLKIT_LISTENER, NMPolkitListenerClass))

GType nm_polkit_listener_get_type (void);

NMPolkitListener *nm_polkit_listener_new (GDBusConnection *dbus_connection, gboolean session_agent);

#endif /* __NM_POLKIT_LISTENER_H__ */
