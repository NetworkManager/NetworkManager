/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SUPPLICANT_INTERFACE_H
#define NM_SUPPLICANT_INTERFACE_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-supplicant-types.h"

G_BEGIN_DECLS

/*
 * Supplicant interface states
 *   The states are linear, ie INIT -> READY -> DOWN and state may only be
 *   changed in one direction.  If an interface reaches the DOWN state, it
 *   cannot be re-initialized; it must be torn down and a new one created.
 *
 * INIT:  interface has been created, but cannot be used yet; it is waiting
 *             for pending requests of the supplicant to complete.
 * READY: interface is ready for use
 * DOWN:  interface has been removed or has otherwise been made invalid; it
 *             must be torn down.
 *
 * Note: LAST is an invalid state and only used for boundary checking.
 */
enum {
	NM_SUPPLICANT_INTERFACE_STATE_INIT = 0,
	NM_SUPPLICANT_INTERFACE_STATE_STARTING,
	NM_SUPPLICANT_INTERFACE_STATE_READY,
	NM_SUPPLICANT_INTERFACE_STATE_DOWN,
	NM_SUPPLICANT_INTERFACE_STATE_LAST
};


/*
 * Supplicant interface connection states
 *   The wpa_supplicant state for the connection.
 */
enum {
	NM_SUPPLICANT_INTERFACE_CON_STATE_DISCONNECTED = 0,
	NM_SUPPLICANT_INTERFACE_CON_STATE_INACTIVE,
	NM_SUPPLICANT_INTERFACE_CON_STATE_SCANNING,
	NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATING,
	NM_SUPPLICANT_INTERFACE_CON_STATE_ASSOCIATED,
	NM_SUPPLICANT_INTERFACE_CON_STATE_4WAY_HANDSHAKE,
	NM_SUPPLICANT_INTERFACE_CON_STATE_GROUP_HANDSHAKE,
	NM_SUPPLICANT_INTERFACE_CON_STATE_COMPLETED,
	NM_SUPPLICANT_INTERFACE_CON_STATE_LAST
};

#define NM_TYPE_SUPPLICANT_INTERFACE            (nm_supplicant_interface_get_type ())
#define NM_SUPPLICANT_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterface))
#define NM_SUPPLICANT_INTERFACE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))
#define NM_IS_SUPPLICANT_INTERFACE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_IS_SUPPLICANT_INTERFACE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_SUPPLICANT_INTERFACE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))

struct _NMSupplicantInterface {
	GObject parent;
};

typedef struct {
	GObjectClass parent;

	/* Signals */

	/* change in the interface's state */
	void (*state)            (NMSupplicantInterface * iface,
	                          guint32 new_state,
	                          guint32 old_state);

	/* interface was removed by the supplicant */
	void (*removed)          (NMSupplicantInterface * iface);

	/* interface saw a new access point from a scan */
	void (*scanned_ap)       (NMSupplicantInterface * iface,
	                          DBusMessage * message);

	/* result of a wireless scan request */
	void (*scan_req_result)  (NMSupplicantInterface * iface,
	                          gboolean success);

	/* scan results returned from supplicant */
	void (*scan_results)     (NMSupplicantInterface * iface,
	                          guint num_bssids);

	/* link state of the device's connection */
	void (*connection_state) (NMSupplicantInterface * iface,
	                          guint32 new_state,
	                          guint32 old_state);

	/* an error occurred during a connection request */
	void (*connection_error) (NMSupplicantInterface * iface,
	                          const char * name,
	                          const char * message);
} NMSupplicantInterfaceClass;


GType nm_supplicant_interface_get_type (void);

NMSupplicantInterface * nm_supplicant_interface_new (NMSupplicantManager * smgr,
                                                     const char *ifname,
                                                     gboolean is_wireless);

gboolean nm_supplicant_interface_set_config (NMSupplicantInterface * iface,
                                             NMSupplicantConfig * cfg);

void nm_supplicant_interface_disconnect (NMSupplicantInterface * iface);

const char * nm_supplicant_interface_get_device (NMSupplicantInterface * iface);

gboolean nm_supplicant_interface_request_scan (NMSupplicantInterface * self);

guint32 nm_supplicant_interface_get_state (NMSupplicantInterface * self);

guint32 nm_supplicant_interface_get_connection_state (NMSupplicantInterface * self);

const char *nm_supplicant_interface_state_to_string (guint32 state);

const char *nm_supplicant_interface_connection_state_to_string (guint32 state);

gboolean nm_supplicant_interface_get_scanning (NMSupplicantInterface *self);

G_END_DECLS

#endif	/* NM_SUPPLICANT_INTERFACE_H */
