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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_INTERFACE_H__
#define __NETWORKMANAGER_SUPPLICANT_INTERFACE_H__

#include "nm-supplicant-types.h"

/*
 * Supplicant interface states
 *   A mix of wpa_supplicant interface states and internal states.
 */
enum {
	NM_SUPPLICANT_INTERFACE_STATE_INIT = 0,
	NM_SUPPLICANT_INTERFACE_STATE_STARTING,
	NM_SUPPLICANT_INTERFACE_STATE_READY,
	NM_SUPPLICANT_INTERFACE_STATE_DISABLED,
	NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED,
	NM_SUPPLICANT_INTERFACE_STATE_INACTIVE,
	NM_SUPPLICANT_INTERFACE_STATE_SCANNING,
	NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING,
	NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING,
	NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED,
	NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE,
	NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE,
	NM_SUPPLICANT_INTERFACE_STATE_COMPLETED,
	NM_SUPPLICANT_INTERFACE_STATE_DOWN,
	NM_SUPPLICANT_INTERFACE_STATE_LAST
};

#define NM_TYPE_SUPPLICANT_INTERFACE            (nm_supplicant_interface_get_type ())
#define NM_SUPPLICANT_INTERFACE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterface))
#define NM_SUPPLICANT_INTERFACE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))
#define NM_IS_SUPPLICANT_INTERFACE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_IS_SUPPLICANT_INTERFACE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_INTERFACE))
#define NM_SUPPLICANT_INTERFACE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfaceClass))

/* Properties */
#define NM_SUPPLICANT_INTERFACE_IFACE            "iface"
#define NM_SUPPLICANT_INTERFACE_SCANNING         "scanning"
#define NM_SUPPLICANT_INTERFACE_CURRENT_BSS      "current-bss"
#define NM_SUPPLICANT_INTERFACE_IS_WIRELESS      "is-wireless"
#define NM_SUPPLICANT_INTERFACE_FAST_SUPPORTED   "fast-supported"
#define NM_SUPPLICANT_INTERFACE_AP_SUPPORT       "ap-support"

/* Signals */
#define NM_SUPPLICANT_INTERFACE_STATE            "state"
#define NM_SUPPLICANT_INTERFACE_REMOVED          "removed"
#define NM_SUPPLICANT_INTERFACE_NEW_BSS          "new-bss"
#define NM_SUPPLICANT_INTERFACE_BSS_UPDATED      "bss-updated"
#define NM_SUPPLICANT_INTERFACE_BSS_REMOVED      "bss-removed"
#define NM_SUPPLICANT_INTERFACE_SCAN_DONE        "scan-done"
#define NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR "connection-error"
#define NM_SUPPLICANT_INTERFACE_CREDENTIALS_REQUEST "credentials-request"

typedef struct _NMSupplicantInterfaceClass NMSupplicantInterfaceClass;

GType nm_supplicant_interface_get_type (void);

NMSupplicantInterface * nm_supplicant_interface_new (const char *ifname,
                                                     gboolean is_wireless,
                                                     gboolean fast_supported,
                                                     NMSupplicantFeature ap_support);

void nm_supplicant_interface_set_supplicant_available (NMSupplicantInterface *self,
                                                       gboolean available);

gboolean nm_supplicant_interface_set_config (NMSupplicantInterface * iface,
                                             NMSupplicantConfig * cfg,
                                             GError **error);

void nm_supplicant_interface_disconnect (NMSupplicantInterface * iface);

const char *nm_supplicant_interface_get_object_path (NMSupplicantInterface * iface);

gboolean nm_supplicant_interface_request_scan (NMSupplicantInterface * self, const GPtrArray *ssids);

guint32 nm_supplicant_interface_get_state (NMSupplicantInterface * self);

const char *nm_supplicant_interface_state_to_string (guint32 state);

gboolean nm_supplicant_interface_get_scanning (NMSupplicantInterface *self);

const char *nm_supplicant_interface_get_current_bss (NMSupplicantInterface *self);

gint32 nm_supplicant_interface_get_last_scan_time (NMSupplicantInterface *self);

const char *nm_supplicant_interface_get_ifname (NMSupplicantInterface *self);

guint nm_supplicant_interface_get_max_scan_ssids (NMSupplicantInterface *self);

gboolean nm_supplicant_interface_get_has_credentials_request (NMSupplicantInterface *self);

gboolean nm_supplicant_interface_credentials_reply (NMSupplicantInterface *self,
                                                    const char *field,
                                                    const char *value,
                                                    GError **error);

NMSupplicantFeature nm_supplicant_interface_get_ap_support (NMSupplicantInterface *self);

void nm_supplicant_interface_set_ap_support (NMSupplicantInterface *self,
                                             NMSupplicantFeature apmode);

#endif	/* NM_SUPPLICANT_INTERFACE_H */
