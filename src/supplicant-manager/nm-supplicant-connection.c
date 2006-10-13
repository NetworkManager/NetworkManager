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
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <glib.h>

#include "nm-supplicant-connection.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-utils.h"

#define NM_SUPPLICANT_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_CONNECTION, \
                                                 NMSupplicantConnectionPrivate))


static void nm_supplicant_connection_set_device (NMSupplicantConnection *con,
                                                 NMDevice *dev);


struct _NMSupplicantConnectionPrivate
{
	NMDevice *dev;
	GHashTable *config;
	gboolean	dispose_has_run;
};

NMSupplicantConnection *
nm_supplicant_connection_new (NMDevice *dev)
{
	NMSupplicantConnection * scfg;

	g_return_val_if_fail (dev != NULL, NULL);

	scfg = g_object_new (NM_TYPE_SUPPLICANT_CONNECTION, NULL);
	nm_supplicant_connection_set_device (scfg, dev);
	return scfg;
}

static void
nm_supplicant_connection_init (NMSupplicantConnection * self)
{
	self->priv = NM_SUPPLICANT_CONNECTION_GET_PRIVATE (self);
	self->priv->config = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                                            g_free);
	self->priv->dispose_has_run = FALSE;
}

static void
nm_supplicant_connection_set_device (NMSupplicantConnection *self,
                                     NMDevice *dev)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (dev != NULL);

	g_object_ref (G_OBJECT (dev));
	self->priv->dev = dev;
}

gboolean
nm_supplicant_connection_add_option (NMSupplicantConnection *self,
                                     const char * key,
                                     const char * value)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (!nm_supplicant_settings_verify_setting (key, value)) {
		nm_debug ("Key '%s' and/or value '%s' invalid.", key, value);
		return FALSE;
	}

	if (g_hash_table_lookup (self->priv->config, key)) {
		nm_debug ("Key '%s' already in table.", key);
		return FALSE;
	}

	g_hash_table_insert (self->priv->config, g_strdup (key), g_strdup (value));
	return TRUE;
}

gboolean
nm_supplicant_connection_remove_option (NMSupplicantConnection *self,
                                        const char * key)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	return g_hash_table_remove (self->priv->config, key);
}

static void
nm_supplicant_connection_dispose (GObject *object)
{
	NMSupplicantConnection *		self = NM_SUPPLICANT_CONNECTION (object);
	NMSupplicantConnectionClass *	klass;
	GObjectClass *				parent_class;  

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
	if (self->priv->dev) {
		g_object_unref (G_OBJECT (self->priv->dev));
		self->priv->dev = NULL;
	}

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_CONNECTION_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_CONNECTION));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_supplicant_connection_finalize (GObject *object)
{
	NMSupplicantConnection *		self = NM_SUPPLICANT_CONNECTION (object);
	NMSupplicantConnectionClass *	klass;
	GObjectClass *		parent_class;  

	/* Complete object destruction */
	g_hash_table_destroy (self->priv->config);

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_CONNECTION_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_CONNECTION));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}


static void
nm_supplicant_connection_class_init (NMSupplicantConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_supplicant_connection_dispose;
	object_class->finalize = nm_supplicant_connection_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantConnectionPrivate));
}

GType
nm_supplicant_connection_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMSupplicantConnectionClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_supplicant_connection_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMSupplicantConnection),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_supplicant_connection_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMSupplicantConnection",
								 &info, 0);
	}
	return type;
}
