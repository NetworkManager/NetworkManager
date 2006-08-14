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

#ifndef NM_AP_SECURITY_H
#define NM_AP_SECURITY_H

#include <glib-object.h>
#include <dbus/dbus.h>

/* Grr */
#ifndef NM_DEVICE_802_11_WIRELESS_DEFINED
#define NM_DEVICE_802_11_WIRELESS_DEFINED
typedef struct _NMDevice80211Wireless NMDevice80211Wireless;
#endif

G_BEGIN_DECLS

#define NM_TYPE_AP_SECURITY			(nm_ap_security_get_type ())
#define NM_AP_SECURITY(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AP_SECURITY, NMAPSecurity))
#define NM_AP_SECURITY_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AP_SECURITY, NMAPSecurityClass))
#define NM_IS_AP_SECURITY(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AP_SECURITY))
#define NM_IS_AP_SECURITY_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AP_SECURITY))
#define NM_AP_SECURITY_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AP_SECURITY, NMAPSecurityClass))

typedef struct _NMAPSecurity NMAPSecurity;
typedef struct _NMAPSecurityClass NMAPSecurityClass;
typedef struct _NMAPSecurityPrivate NMAPSecurityPrivate;

struct _NMAPSecurity
{
	GObject parent;

	/*< private >*/
	NMAPSecurityPrivate *priv;
};

struct NMAccessPoint;
struct wpa_ctrl;

struct _NMAPSecurityClass
{
	GObjectClass parent;

	/* class members */
	NMAPSecurity *	(*copy_constructor_func)	(NMAPSecurity *self);

	int	(*serialize_func)				(NMAPSecurity *self, DBusMessageIter *iter);

	gboolean	(*write_supplicant_config_func)(NMAPSecurity *self,
									  struct wpa_ctrl *ctrl,
									  int nwid,
									  gboolean adhoc);

	guint32 (*get_default_capabilities_func)(NMAPSecurity *self);
	gboolean (*get_authentication_required_func)(NMAPSecurity *self);
};


GType nm_ap_security_get_type (void);

NMAPSecurity *	nm_ap_security_new_copy (NMAPSecurity *self);

NMAPSecurity * nm_ap_security_new (int we_cipher);

NMAPSecurity *	nm_ap_security_new_deserialize (DBusMessageIter *iter);

NMAPSecurity *	nm_ap_security_new_from_ap (struct NMAccessPoint *ap);

int			nm_ap_security_get_we_cipher (NMAPSecurity *self);

const char *	nm_ap_security_get_key (NMAPSecurity *self);

int			nm_ap_security_serialize (NMAPSecurity *self,
									DBusMessageIter *iter);

gboolean		nm_ap_security_write_supplicant_config (NMAPSecurity *self,
									struct wpa_ctrl *ctrl,
									int nwid,
									gboolean adhoc);

const char *	nm_ap_security_get_description (NMAPSecurity *self);

guint32		nm_ap_security_get_default_capabilities (NMAPSecurity *self);

gboolean		nm_ap_security_get_authentication_required (NMAPSecurity *self);

G_END_DECLS

#endif	/* NM_AP_SECURITY_H */
