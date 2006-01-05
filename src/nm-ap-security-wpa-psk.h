/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_AP_SECURITY_WPA_PSK_H
#define NM_AP_SECURITY_WPA_PSK_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-ap-security.h"

#define NM_TYPE_AP_SECURITY_WPA_PSK			(nm_ap_security_wpa_psk_get_type ())
#define NM_AP_SECURITY_WPA_PSK(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AP_SECURITY_WPA_PSK, NMAPSecurityWPA_PSK))
#define NM_AP_SECURITY_WPA_PSK_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AP_SECURITY_WPA_PSK, NMAPSecurityWPA_PSKClass))
#define NM_IS_AP_SECURITY_WPA_PSK(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AP_SECURITY_WPA_PSK))
#define NM_IS_AP_SECURITY_WPA_PSK_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AP_SECURITY_WPA_PSK))
#define NM_AP_SECURITY_WPA_PSK_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AP_SECURITY_WPA_PSK, NMAPSecurityWPA_PSKClass))

typedef struct _NMAPSecurityWPA_PSK NMAPSecurityWPA_PSK;
typedef struct _NMAPSecurityWPA_PSKClass NMAPSecurityWPA_PSKClass;
typedef struct _NMAPSecurityWPA_PSKPrivate NMAPSecurityWPA_PSKPrivate;

struct _NMAPSecurityWPA_PSK
{
	NMAPSecurity parent;

	/*< private >*/
	NMAPSecurityWPA_PSKPrivate *priv;
};

struct _NMAPSecurityWPA_PSKClass
{
	NMAPSecurityClass parent;
};


GType nm_ap_security_wpa_psk_get_type (void);

NMAPSecurityWPA_PSK * nm_ap_security_wpa_psk_new_deserialize (DBusMessageIter *iter, int we_cipher);

struct NMAccessPoint;
NMAPSecurityWPA_PSK * nm_ap_security_wpa_psk_new_from_ap (struct NMAccessPoint *ap, int we_cipher);

#endif	/* NM_AP_SECURITY_WPA_PSK_H */
