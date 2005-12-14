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
#include <dbus/dbus.h>
#include <iwlib.h>

#include "nm-ap-security.h"
#include "nm-ap-security-private.h"
#include "nm-ap-security-wep.h"
#include "nm-ap-security-wpa-psk.h"

#define NM_AP_SECURITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY, NMAPSecurityPrivate))

struct _NMAPSecurityPrivate
{
	int		we_cipher;
	char *	key;

	gboolean	dispose_has_run;
};

static GObjectClass *parent_class = NULL;

static NMAPSecurity *
nm_ap_security_new (int we_cipher)
{
	NMAPSecurity * security;

	security = g_object_new (NM_TYPE_AP_SECURITY, NULL);
	security->priv->we_cipher = we_cipher;
	return security;
}


NMAPSecurity *
nm_ap_security_new_from_dbus_message (DBusMessageIter *iter)
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
				security = NM_AP_SECURITY (nm_ap_security_wep_new_from_dbus_message (iter, we_cipher));
				break;

			case IW_AUTH_CIPHER_TKIP:
			case IW_AUTH_CIPHER_CCMP:
				security = NM_AP_SECURITY (nm_ap_security_wpa_psk_new_from_dbus_message (iter, we_cipher));
				break;

			default:
				break;
		}
	}

out:
	return security;
}

void nm_ap_security_write_wpa_supplicant_config (NMAPSecurity *self, int fd)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (fd >= 0);

	if (self->priv->dispose_has_run)
		return;

	NM_AP_SECURITY_GET_CLASS (self)->write_wpa_supplicant_config_func (self, fd);
}

void
nm_ap_security_set_we_cipher (NMAPSecurity *self, int we_cipher)
{
	g_return_if_fail (self != NULL);

	/* Ensure the cipher is valid */
	g_return_if_fail (
		   (we_cipher == IW_AUTH_CIPHER_NONE)
		|| (we_cipher == IW_AUTH_CIPHER_WEP40)
		|| (we_cipher == IW_AUTH_CIPHER_WEP104)
		|| (we_cipher == IW_AUTH_CIPHER_TKIP)
		|| (we_cipher == IW_AUTH_CIPHER_CCMP));

	self->priv->we_cipher = we_cipher;
}

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

static void 
real_write_wpa_supplicant_config (NMAPSecurity *self, int fd)
{
}

int nm_ap_security_get_we_cipher (NMAPSecurity *self)
{
	NMAPSecurityPrivate *priv;

	g_return_val_if_fail (self != NULL, -1);

	priv = NM_AP_SECURITY_GET_PRIVATE (self);

	return priv->we_cipher;
}

const char * nm_ap_security_get_key (NMAPSecurity *self)
{
	NMAPSecurityPrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);

	priv = NM_AP_SECURITY_GET_PRIVATE (self);

	return priv->key;
}

static void
nm_ap_security_init (NMAPSecurity * self)
{
	self->priv = NM_AP_SECURITY_GET_PRIVATE (self);
	self->priv->dispose_has_run = FALSE;
	self->priv->we_cipher = IW_AUTH_CIPHER_NONE;
	self->priv->key = NULL;
}

static void
nm_ap_security_dispose (GObject *object)
{
	NMAPSecurity *self = (NMAPSecurity *) object;

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
	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
nm_ap_security_finalize (GObject *object)
{
	NMAPSecurity *self = (NMAPSecurity *) object;

	/* Complete object destruction */
	g_free (self->priv->key);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (parent_class)->finalize (object);
}


static void
nm_ap_security_class_init (NMAPSecurityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_ap_security_dispose;
	object_class->finalize = nm_ap_security_finalize;

	klass->write_wpa_supplicant_config_func = real_write_wpa_supplicant_config;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityPrivate));
}

GType
nm_ap_security_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityClass),
			NULL,   /* base_init */
			NULL,   /* base_finalize */
			(GClassInitFunc) nm_ap_security_class_init,
			NULL,   /* class_finalize */
			NULL,   /* class_data */
			sizeof (NMAPSecurity),
			0,      /* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_init
		};
		type = g_type_register_static (G_TYPE_OBJECT,
					       "NMAPSecurity",
					       &info, 0);
	}
	return type;
}
