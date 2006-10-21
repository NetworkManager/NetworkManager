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
#include "nm-ap-security-private.h"
#include "nm-ap-security-wep.h"
#include "nm-ap-security-wpa-psk.h"
#include "nm-ap-security-wpa-eap.h"
#include "nm-ap-security-leap.h"
#include "nm-device-802-11-wireless.h"
#include "wpa_ctrl.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

#define NM_AP_SECURITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY, NMAPSecurityPrivate))

struct _NMAPSecurityPrivate
{
	int		we_cipher;
	char *	key;
	char *	description;

	gboolean	dispose_has_run;
};

NMAPSecurity *
nm_ap_security_new (int we_cipher)
{
	NMAPSecurity * security;

	security = g_object_new (NM_TYPE_AP_SECURITY, NULL);
	security->priv->we_cipher = we_cipher;
	security->priv->key = NULL;
	return security;
}


NMAPSecurity *
nm_ap_security_new_deserialize (DBusMessageIter *iter)
{
	NMAPSecurity * security = NULL;
	int we_cipher;

	g_return_val_if_fail (iter != NULL, NULL);

	/* We require the WE cipher (an INT32) first */
	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT32, NULL);

	/* Get and validate WE cipher */
	dbus_message_iter_get_basic (iter, &we_cipher);

	if (we_cipher == IW_AUTH_CIPHER_NONE)
		security = nm_ap_security_new (we_cipher);
	else
	{
		/* Advance to start of cipher-dependent options */
		if (!dbus_message_iter_next (iter))
			goto out;

		switch (we_cipher)
		{
			case IW_AUTH_CIPHER_WEP40:
			case IW_AUTH_CIPHER_WEP104:
				security = NM_AP_SECURITY (nm_ap_security_wep_new_deserialize (iter, we_cipher));
				break;

			case NM_AUTH_TYPE_WPA_PSK_AUTO:
			case IW_AUTH_CIPHER_TKIP:
			case IW_AUTH_CIPHER_CCMP:
				security = NM_AP_SECURITY (nm_ap_security_wpa_psk_new_deserialize (iter, we_cipher));
				break;

			case NM_AUTH_TYPE_WPA_EAP:
				security = NM_AP_SECURITY (nm_ap_security_wpa_eap_new_deserialize (iter));
				break;

			case NM_AUTH_TYPE_LEAP:
				security = NM_AP_SECURITY (nm_ap_security_leap_new_deserialize (iter));
				break;

			default:
				nm_warning ("Unmatched cipher %d", we_cipher);
				break;
		}
	}

out:
	return security;
}


#define WPA2_CCMP_PSK	(NM_802_11_CAP_PROTO_WPA2 | NM_802_11_CAP_CIPHER_CCMP | NM_802_11_CAP_KEY_MGMT_PSK)
#define WPA2_TKIP_PSK	(NM_802_11_CAP_PROTO_WPA2 | NM_802_11_CAP_CIPHER_TKIP | NM_802_11_CAP_KEY_MGMT_PSK)
#define WPA2_EAP		(NM_802_11_CAP_PROTO_WPA2 | NM_802_11_CAP_KEY_MGMT_802_1X)
#define WPA_CCMP_PSK	(NM_802_11_CAP_PROTO_WPA | NM_802_11_CAP_CIPHER_CCMP | NM_802_11_CAP_KEY_MGMT_PSK)
#define WPA_TKIP_PSK	(NM_802_11_CAP_PROTO_WPA | NM_802_11_CAP_CIPHER_TKIP | NM_802_11_CAP_KEY_MGMT_PSK)
#define WPA_EAP		(NM_802_11_CAP_PROTO_WPA | NM_802_11_CAP_KEY_MGMT_802_1X)
#define WEP_WEP104		(NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP104)
#define WEP_WEP40		(NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP40)
#define LEAP			(NM_802_11_CAP_KEY_MGMT_802_1X)
NMAPSecurity *
nm_ap_security_new_from_ap (NMAccessPoint *ap)
{
	NMAPSecurity *	security = NULL;
	guint32		caps;

	g_return_val_if_fail (ap != NULL, NULL);

	/* Deteremine best encryption algorithm to use */
	caps = nm_ap_get_capabilities (ap);
	if (((caps & WPA_CCMP_PSK) == WPA_CCMP_PSK) || ((caps & WPA2_CCMP_PSK) == WPA2_CCMP_PSK))
		security = NM_AP_SECURITY (nm_ap_security_wpa_psk_new_from_ap (ap, IW_AUTH_CIPHER_CCMP));
	else if (((caps & WPA_TKIP_PSK) == WPA_TKIP_PSK) || ((caps & WPA2_TKIP_PSK) == WPA2_TKIP_PSK))
		security = NM_AP_SECURITY (nm_ap_security_wpa_psk_new_from_ap (ap, IW_AUTH_CIPHER_TKIP));
	else if (((caps & WPA_EAP) == WPA_EAP) || ((caps & WPA2_EAP) == WPA2_EAP))
		security = NM_AP_SECURITY (nm_ap_security_wpa_eap_new_from_ap (ap));
	else if ((caps & WEP_WEP104) == WEP_WEP104)
		security = NM_AP_SECURITY (nm_ap_security_wep_new_from_ap (ap, IW_AUTH_CIPHER_WEP104));
	else if ((caps & WEP_WEP40) == WEP_WEP40)
		security = NM_AP_SECURITY (nm_ap_security_wep_new_from_ap (ap, IW_AUTH_CIPHER_WEP40));
	else if ((caps & LEAP) == LEAP)
		security = NM_AP_SECURITY (nm_ap_security_leap_new_from_ap (ap));
	else if (!nm_ap_get_encrypted (ap))
		security = nm_ap_security_new (IW_AUTH_CIPHER_NONE);

	return security;
}


guint32
nm_ap_security_get_default_capabilities (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, NM_802_11_CAP_PROTO_NONE);

	return NM_AP_SECURITY_GET_CLASS (self)->get_default_capabilities_func (self);
}

gboolean
nm_ap_security_get_authentication_required (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	
	return NM_AP_SECURITY_GET_CLASS (self)->get_authentication_required_func (self);
}


gboolean
nm_ap_security_write_supplicant_config (NMAPSecurity *self,
                                        struct wpa_ctrl *ctrl,
                                        int nwid,
                                        gboolean adhoc)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (ctrl != NULL, FALSE);
	g_return_val_if_fail (nwid >= 0, FALSE);

	if (self->priv->dispose_has_run)
		return FALSE;

	return NM_AP_SECURITY_GET_CLASS (self)->write_supplicant_config_func (self,
			ctrl, nwid, adhoc);
}

void
nm_ap_security_set_we_cipher (NMAPSecurity *self, int we_cipher)
{
	g_return_if_fail (self != NULL);

	/* Ensure that the cipher is valid */
	g_return_if_fail (
		   (we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO)
		|| (we_cipher == IW_AUTH_CIPHER_NONE)
		|| (we_cipher == IW_AUTH_CIPHER_WEP40)
		|| (we_cipher == IW_AUTH_CIPHER_WEP104)
		|| (we_cipher == IW_AUTH_CIPHER_TKIP)
		|| (we_cipher == IW_AUTH_CIPHER_CCMP)
		|| (we_cipher == NM_AUTH_TYPE_WPA_EAP)
		|| (we_cipher == NM_AUTH_TYPE_LEAP));

	self->priv->we_cipher = we_cipher;
}

/*
 * nm_ap_security_set_key - set the encryption key for a given AP
 *
 */
void
nm_ap_security_set_key (NMAPSecurity *self, const char *key, int key_len)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (key_len > 0);

	if (self->priv->key)
		g_free (self->priv->key);
	self->priv->key = g_malloc0 (key_len + 1);
	memcpy (self->priv->key, key, key_len);
}

static NMAPSecurity *
real_copy_constructor (NMAPSecurity *self)
{
	NMAPSecurity * dst = nm_ap_security_new (self->priv->we_cipher);

	nm_ap_security_copy_properties (self, dst);
	return dst;
}

static int 
real_serialize (NMAPSecurity *self, DBusMessageIter *iter)
{
	/* Nothing to do */
	return 0;
}

static gboolean 
real_write_supplicant_config (NMAPSecurity *self,
                              struct wpa_ctrl *ctrl,
                              int nwid,
                              gboolean adhoc)
{
	/* Unencrypted network setup */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"SET_NETWORK %i key_mgmt NONE", nwid))
		return FALSE;

	return TRUE;
}

static guint32
real_get_default_capabilities (NMAPSecurity *self)
{
	return NM_802_11_CAP_PROTO_NONE;
}

int
nm_ap_security_get_we_cipher (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, NM_AUTH_TYPE_WPA_PSK_AUTO);

	return self->priv->we_cipher;
}

const char *
nm_ap_security_get_key (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->key;
}

const char *
nm_ap_security_get_description (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return self->priv->description;
}

void
nm_ap_security_set_description (NMAPSecurity *self, const char *desc)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (desc != NULL);

	self->priv->description = (char *) desc;
}

int
nm_ap_security_serialize (NMAPSecurity *self, DBusMessageIter *iter)
{
	dbus_int32_t	dbus_we_cipher;

	g_return_val_if_fail (self != NULL, -1);
	g_return_val_if_fail (iter != NULL, -1);

	if (self->priv->dispose_has_run)
		return -1;

	/* First arg: WE cipher (INT32) */
	dbus_we_cipher = (dbus_int32_t) self->priv->we_cipher;
	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT32, &dbus_we_cipher);

	return NM_AP_SECURITY_GET_CLASS (self)->serialize_func (self, iter);
}

NMAPSecurity *
nm_ap_security_new_copy (NMAPSecurity *self)
{
	g_return_val_if_fail (self != NULL, NULL);

	return NM_AP_SECURITY_GET_CLASS (self)->copy_constructor_func (self);
}

void
nm_ap_security_copy_properties (NMAPSecurity *self, NMAPSecurity *dst)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (dst != NULL);
	g_return_if_fail (self != dst);

	nm_ap_security_set_we_cipher (dst, self->priv->we_cipher);
	if (self->priv->key)
		nm_ap_security_set_key (dst, self->priv->key, strlen (self->priv->key));
	nm_ap_security_set_description (dst, self->priv->description);
}

static void
nm_ap_security_init (NMAPSecurity * self)
{
	self->priv = NM_AP_SECURITY_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
	self->priv->we_cipher = IW_AUTH_CIPHER_NONE;
	self->priv->key = NULL;
	self->priv->description = _("none");
}

static void
nm_ap_security_dispose (GObject *object)
{
	NMAPSecurity *		self = NM_AP_SECURITY (object);
	NMAPSecurityClass *	klass;
	GObjectClass *		parent_class;  

	if (self->priv->dispose_has_run)
		/* If dispose did already run, return. */
		return;

	/* Make sure dispose does not run twice. */
	self->priv->dispose_has_run = TRUE;

	/* 
	 * In dispose, you are supposed to free all types referenced from this
	 * object which might themselves hold a reference to self. Generally,
	 * the most simple solution is to unref all members on which you own a 
	 * reference.
	 */

	/* Chain up to the parent class */
	klass = NM_AP_SECURITY_CLASS (g_type_class_peek (NM_TYPE_AP_SECURITY));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_ap_security_finalize (GObject *object)
{
	NMAPSecurity *		self = NM_AP_SECURITY (object);
	NMAPSecurityClass *	klass;
	GObjectClass *		parent_class;  

	/* Complete object destruction */
	g_free (self->priv->key);

	/* Chain up to the parent class */
	klass = NM_AP_SECURITY_CLASS (g_type_class_peek (NM_TYPE_AP_SECURITY));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}


static void
nm_ap_security_class_init (NMAPSecurityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_ap_security_dispose;
	object_class->finalize = nm_ap_security_finalize;

	klass->copy_constructor_func = real_copy_constructor;
	klass->serialize_func = real_serialize;
	klass->write_supplicant_config_func = real_write_supplicant_config;
	klass->get_default_capabilities_func = real_get_default_capabilities;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityPrivate));
}

GType
nm_ap_security_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_ap_security_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMAPSecurity),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMAPSecurity",
								 &info, 0);
	}
	return type;
}
