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
#include "nm-ap-security-wep.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "NetworkManagerDevice.h"

#define NM_AP_SECURITY_WEP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_WEP, NMAPSecurityWEPPrivate))

struct _NMAPSecurityWEPPrivate
{
	int		auth_algorithm;

	gboolean	dispose_has_run;
};

NMAPSecurityWEP *
nm_ap_security_wep_new_deserialize (DBusMessageIter *iter, int we_cipher)
{
	NMAPSecurityWEP *	security = NULL;
	char *			key = NULL;
	int				key_len;
	int				auth_algorithm;
	DBusMessageIter	subiter;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_WEP40) || (we_cipher == IW_AUTH_CIPHER_WEP104), NULL);

	if (!nmu_security_deserialize_wep (iter, &key, &key_len, &auth_algorithm))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_WEP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);
	nm_ap_security_set_key (NM_AP_SECURITY (security), key, key_len);
	security->priv->auth_algorithm = auth_algorithm;

	if (we_cipher == IW_AUTH_CIPHER_WEP40)
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("40-bit WEP"));
	else
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("104-bit WEP"));

out:
	return security;
}

static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityWEP *	self = NM_AP_SECURITY_WEP (instance);

	if (!nmu_security_serialize_wep (iter,
			nm_ap_security_get_key (instance),
			self->priv->auth_algorithm))
		return -1;
	return 0;
}

static void 
real_write_wpa_supplicant_config (NMAPSecurity *instance, int fd)
{
	NMAPSecurityWEP * self = NM_AP_SECURITY_WEP (instance);
}

static int 
real_device_setup (NMAPSecurity *instance, NMDevice * dev)
{
	NMAPSecurityWEP * self = NM_AP_SECURITY_WEP (instance);

	nm_device_set_enc_key (dev, nm_ap_security_get_key (instance),
			self->priv->auth_algorithm);
	return 0;
}

static void
nm_ap_security_wep_init (NMAPSecurityWEP * self)
{
	self->priv = NM_AP_SECURITY_WEP_GET_PRIVATE (self);
	self->priv->auth_algorithm = IW_AUTH_ALG_OPEN_SYSTEM;
	self->priv->dispose_has_run = FALSE;
}

static void
nm_ap_security_wep_class_init (NMAPSecurityWEPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->serialize_func = real_serialize;
	par_class->write_wpa_supplicant_config_func = real_write_wpa_supplicant_config;
	par_class->device_setup_func = real_device_setup;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityWEPPrivate));
}

GType
nm_ap_security_wep_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityWEPClass),
			NULL,   /* base_init */
			NULL,   /* base_finalize */
			(GClassInitFunc) nm_ap_security_wep_class_init,
			NULL,   /* class_finalize */
			NULL,   /* class_data */
			sizeof (NMAPSecurityWEP),
			0,      /* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_wep_init
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
					       "NMAPSecurityWEP",
					       &info, 0);
	}
	return type;
}
