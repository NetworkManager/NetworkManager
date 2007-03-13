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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2006 Thiago Jung Bauermann <thiago.bauermann@gmail.com>
 */

/* This file is heavily based on nm-ap-security-wpa-eap.c */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "nm-ap-security.h"
#include "nm-ap-security-leap.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerUtils.h"

#define NM_AP_SECURITY_LEAP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_LEAP, NMAPSecurityLEAPPrivate))

struct _NMAPSecurityLEAPPrivate
{
	char *	username;
	char * 	key_mgmt;
};


NMAPSecurityLEAP *
nm_ap_security_leap_new_deserialize (DBusMessageIter *iter)
{
	NMAPSecurityLEAP *	security = NULL;
	char *			username = NULL;
	char *			password = NULL;
	char *			key_mgmt = NULL;

	g_return_val_if_fail (iter != NULL, NULL);

	if (!nmu_security_deserialize_leap (iter, &username, &password, &key_mgmt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_LEAP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), NM_AUTH_TYPE_LEAP);
	if (password)
		nm_ap_security_set_key (NM_AP_SECURITY (security), password, strlen(password));
	if (username)
		security->priv->username = g_strdup (username);
	if (key_mgmt)
		security->priv->key_mgmt = g_strdup (key_mgmt);

	nm_ap_security_set_description (NM_AP_SECURITY (security), _("LEAP"));

out:
	return security;
}


NMAPSecurityLEAP *
nm_ap_security_leap_new_from_ap (NMAccessPoint *ap)
{
	NMAPSecurityLEAP *	security = NULL;

	g_return_val_if_fail (ap != NULL, NULL);

	security = g_object_new (NM_TYPE_AP_SECURITY_LEAP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), NM_AUTH_TYPE_LEAP);
	nm_ap_security_set_description (NM_AP_SECURITY (security), _("LEAP"));

	return security;
}


static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityLEAP * self = NM_AP_SECURITY_LEAP (instance);

	if (!nmu_security_serialize_leap (iter, self->priv->username,
			nm_ap_security_get_key(instance), self->priv->key_mgmt))
		return -1;
	return 0;
}

static gboolean 
real_write_supplicant_config (NMAPSecurity *instance,
                              struct wpa_ctrl *ctrl,
                              int nwid,
                              gboolean user_created)
{
	NMAPSecurityLEAP *	self = NM_AP_SECURITY_LEAP (instance);
	gboolean			success = FALSE;
	char *			msg;
	const char *		password = nm_ap_security_get_key(instance);

	g_return_val_if_fail (nm_ap_security_get_we_cipher (instance) == NM_AUTH_TYPE_LEAP, FALSE);

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i proto WPA", nwid))
		   goto out;

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i key_mgmt %s",
					    nwid, self->priv->key_mgmt))
		   goto out;

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i eap LEAP", nwid))
		goto out;

	if (self->priv->username && strlen (self->priv->username) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i identity \"%s\"",
						    nwid, self->priv->username))
			goto out;

	if (password && strlen (password) > 0)
	{
		msg = g_strdup_printf ("SET_NETWORK %i password <password>", nwid);
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, msg, "SET_NETWORK %i password \"%s\"",
						    nwid, password))
		{
			g_free (msg);
			goto out;
		}
		g_free (msg);
	}

	success = TRUE;

out:
	return success;
}

static guint32
real_get_default_capabilities (NMAPSecurity *instance)
{
	guint32			caps = NM_802_11_CAP_NONE;

	caps |= NM_802_11_CAP_KEY_MGMT_802_1X;

	return caps;
}

static gboolean
real_get_authentication_required (NMAPSecurity *instance)
{
	return TRUE;
}

static NMAPSecurity *
real_copy_constructor (NMAPSecurity *instance)
{
	NMAPSecurityLEAP * dst = g_object_new (NM_TYPE_AP_SECURITY_LEAP, NULL);
	NMAPSecurityLEAP * self = NM_AP_SECURITY_LEAP (instance);

	dst->priv->username = self->priv->username;
	dst->priv->key_mgmt = self->priv->key_mgmt;

	nm_ap_security_copy_properties (NM_AP_SECURITY (self), NM_AP_SECURITY (dst));

	return NM_AP_SECURITY (dst);
}


static void
nm_ap_security_leap_init (NMAPSecurityLEAP * self)
{
	self->priv = NM_AP_SECURITY_LEAP_GET_PRIVATE (self);
	self->priv->username = NULL;
	self->priv->key_mgmt = NULL;
}


static void
nm_ap_security_leap_class_init (NMAPSecurityLEAPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->copy_constructor_func = real_copy_constructor;
	par_class->serialize_func = real_serialize;
	par_class->write_supplicant_config_func = real_write_supplicant_config;
	par_class->get_default_capabilities_func = real_get_default_capabilities;
	par_class->get_authentication_required_func = real_get_authentication_required;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityLEAPPrivate));
}


GType
nm_ap_security_leap_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityLEAPClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_ap_security_leap_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMAPSecurityLEAP),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_leap_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
					       		 "NMAPSecurityLEAP",
					       		 &info, 0);
	}
	return type;
}
