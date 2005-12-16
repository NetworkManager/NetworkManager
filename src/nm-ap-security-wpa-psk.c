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

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "nm-ap-security.h"
#include "nm-ap-security-wpa-psk.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "NetworkManagerDevice.h"

#define NM_AP_SECURITY_WPA_PSK_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_WPA_PSK, NMAPSecurityWPA_PSKPrivate))

struct _NMAPSecurityWPA_PSKPrivate
{
	int		wpa_version;
	int		key_mgt;

	gboolean	dispose_has_run;
};

NMAPSecurityWPA_PSK *
nm_ap_security_wpa_psk_new_deserialize (DBusMessageIter *iter, int we_cipher)
{
	NMAPSecurityWPA_PSK *	security = NULL;
	char *				key;
	int					key_len;
	int					wpa_version;
	int					key_mgt;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_TKIP) || (we_cipher == IW_AUTH_CIPHER_CCMP), NULL);

	if (!nmu_security_deserialize_wpa_psk (iter, &key, &key_len, &wpa_version, &key_mgt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_WPA_PSK, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);
	nm_ap_security_set_key (NM_AP_SECURITY (security), key, key_len);
	security->priv->wpa_version = wpa_version;
	security->priv->key_mgt = key_mgt;

	if (we_cipher == IW_AUTH_CIPHER_TKIP)
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA TKIP"));
	else
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA CCMP"));

out:
	return security;
}

static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);

	if (!nmu_security_serialize_wpa_psk (iter,
			nm_ap_security_get_key (instance),
			self->priv->wpa_version,
			self->priv->key_mgt))
		return -1;
	return 0;
}

static void 
real_write_wpa_supplicant_config (NMAPSecurity *instance, int fd)
{
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);
}

static int 
real_device_setup (NMAPSecurity *self, NMDevice * dev)
{
	/* Stub; should be farmed out to wpa_supplicant eventually */
	return 0;
}

static void
nm_ap_security_wpa_psk_init (NMAPSecurityWPA_PSK * self)
{
	self->priv = NM_AP_SECURITY_WPA_PSK_GET_PRIVATE (self);
	self->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
	self->priv->key_mgt = IW_AUTH_KEY_MGMT_PSK;
	self->priv->dispose_has_run = FALSE;
}

static void
nm_ap_security_wpa_psk_class_init (NMAPSecurityWPA_PSKClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->write_wpa_supplicant_config_func = real_write_wpa_supplicant_config;
	par_class->device_setup_func = real_device_setup;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityWPA_PSKPrivate));
}

GType
nm_ap_security_wpa_psk_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityWPA_PSKClass),
			NULL,   /* base_init */
			NULL,   /* base_finalize */
			(GClassInitFunc) nm_ap_security_wpa_psk_class_init,
			NULL,   /* class_finalize */
			NULL,   /* class_data */
			sizeof (NMAPSecurityWPA_PSK),
			0,      /* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_wpa_psk_init
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
					       "NMAPSecurityWPA_PSK",
					       &info, 0);
	}
	return type;
}
