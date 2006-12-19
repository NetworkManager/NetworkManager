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

#include <string.h>
#include <glib.h>

#include "nm-supplicant-config.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-utils.h"
#include "dbus-dict-helpers.h"
#include "cipher.h"

#define NM_SUPPLICANT_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                             NM_TYPE_SUPPLICANT_CONFIG, \
                                             NMSupplicantConfigPrivate))


static void nm_supplicant_config_set_device (NMSupplicantConfig *con,
                                             NMDevice *dev);


struct option {
	char * key;
	char * value;
	guint32 len;
	enum OptType type;
};

struct _NMSupplicantConfigPrivate
{
	NMDevice * dev;
	GSList *   config;
	guint32    ap_scan;
	gboolean   dispose_has_run;
};

NMSupplicantConfig *
nm_supplicant_config_new (NMDevice *dev)
{
	NMSupplicantConfig * scfg;

	g_return_val_if_fail (dev != NULL, NULL);

	scfg = g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
	nm_supplicant_config_set_device (scfg, dev);
	return scfg;
}

static void
nm_supplicant_config_init (NMSupplicantConfig * self)
{
	self->priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);
	self->priv->config = NULL;
	self->priv->ap_scan = 1;
	self->priv->dispose_has_run = FALSE;
}

static void
nm_supplicant_config_set_device (NMSupplicantConfig *self,
                                 NMDevice *dev)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (dev != NULL);

	g_object_ref (G_OBJECT (dev));
	self->priv->dev = dev;
}

gboolean
nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                 const char * key,
                                 const char * value,
                                 gint32 len)
{
	GSList * elt;
	struct option * opt;
	OptType type;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (len < 0)
		len = strlen (value);

	type = nm_supplicant_settings_verify_setting (key, value, len);
	if (type == TYPE_INVALID) {
		char buf[255];
		memset (&buf[0], 0, sizeof (buf));
		memcpy (&buf[0], value, len > 254 ? 254 : len);
		nm_debug ("Key '%s' and/or value '%s' invalid.", key, buf);
		return FALSE;
	}

	for (elt = self->priv->config; elt; elt = g_slist_next (elt)) {
		struct option * tmp_opt = (struct option *) elt->data;

		if (strcmp (tmp_opt->key, key) == 0) {
			nm_debug ("Key '%s' already in table.", key);
			return FALSE;
		}
	}

	opt = g_slice_new0 (struct option);
	if (opt == NULL) {
		nm_debug ("Couldn't allocate memory for new config option.");
		return FALSE;
	}
	opt->key = g_strdup (key);
	if (opt->key == NULL) {
		nm_debug ("Couldn't allocate memory for new config option key.");
		g_slice_free (struct option, opt);
		return FALSE;
	}
	opt->value = g_malloc0 (sizeof (char) * len);
	if (opt->value == NULL) {
		nm_debug ("Couldn't allocate memory for new config option value.");
		g_free (opt->key);
		g_slice_free (struct option, opt);
		return FALSE;
	}
	memcpy (opt->value, value, len);

	opt->len = len;
	opt->type = type;	
	self->priv->config = g_slist_append (self->priv->config, opt);

	return TRUE;
}

static void
free_option (struct option * opt)
{
	g_return_if_fail (opt != NULL);
	g_free (opt->key);
	g_free (opt->value);
}

gboolean
nm_supplicant_config_remove_option (NMSupplicantConfig *self,
                                    const char * key)
{
	GSList * elt;
	GSList * found = NULL;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	for (elt = self->priv->config; elt; elt = g_slist_next (elt)) {
		struct option * opt = (struct option *) elt->data;

		if (strcmp (opt->key, key) == 0) {
			found = elt;
			break;
		}
	}

	if (!found)
		return FALSE;

	self->priv->config = g_slist_remove_link (self->priv->config, found);
	free_option (found->data);
	g_slice_free (struct option, found->data);
	g_slist_free1 (found);
	return TRUE;
}

static void
nm_supplicant_config_dispose (GObject *object)
{
	NMSupplicantConfig *		self = NM_SUPPLICANT_CONFIG (object);
	NMSupplicantConfigClass *	klass;
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
	klass = NM_SUPPLICANT_CONFIG_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_CONFIG));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->dispose (object);
}

static void
nm_supplicant_config_finalize (GObject *object)
{
	NMSupplicantConfig *      self = NM_SUPPLICANT_CONFIG (object);
	NMSupplicantConfigClass * klass;
	GObjectClass *            parent_class;  
	GSList *                  elt;

	/* Complete object destruction */
	for (elt = self->priv->config; elt; elt = g_slist_next (elt)) {
		free_option (elt->data);
		g_slice_free (struct option, elt->data);
	}
	g_slist_free (self->priv->config);
	self->priv->config = NULL;

	/* Chain up to the parent class */
	klass = NM_SUPPLICANT_CONFIG_CLASS (g_type_class_peek (NM_TYPE_SUPPLICANT_CONFIG));
	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	parent_class->finalize (object);
}


static void
nm_supplicant_config_class_init (NMSupplicantConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_supplicant_config_dispose;
	object_class->finalize = nm_supplicant_config_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantConfigPrivate));
}

GType
nm_supplicant_config_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMSupplicantConfigClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_supplicant_config_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMSupplicantConfig),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_supplicant_config_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMSupplicantConfig",
								 &info, 0);
	}
	return type;
}

guint32
nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self)
{
	g_return_val_if_fail (self != NULL, 1);

	return self->priv->ap_scan;
}

void
nm_supplicant_config_set_ap_scan (NMSupplicantConfig * self,
                                  guint32 ap_scan)
{
	g_return_if_fail (self != NULL);
	g_return_if_fail (ap_scan >= 0 && ap_scan <=2);

	self->priv->ap_scan = ap_scan;
}

gboolean
nm_supplicant_config_add_to_dbus_message (NMSupplicantConfig * self,
                                          DBusMessage * message)
{
	GSList * elt;
	DBusMessageIter iter, iter_dict;
	gboolean success = FALSE;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	dbus_message_iter_init_append (message, &iter);

	if (!nmu_dbus_dict_open_write (&iter, &iter_dict)) {
		nm_warning ("dict open write failed!");
		goto out;
	}

	for (elt = self->priv->config; elt; elt = g_slist_next (elt)) {
		struct option * opt = (struct option *) elt->data;

		switch (opt->type) {
			case TYPE_INT:
				if (!nmu_dbus_dict_append_string (&iter_dict, opt->key, opt->value)) {
					nm_warning ("couldn't append INT option '%s' to dict", opt->key);
					goto out;
				}
				break;

			case TYPE_KEYWORD:
				if (!nmu_dbus_dict_append_string (&iter_dict, opt->key, opt->value)) {
					nm_warning ("couldn't append KEYWORD option '%s' to dict", opt->key);
					goto out;
				}
				break;

			case TYPE_BYTES:
				{
					if (!nmu_dbus_dict_append_byte_array (&iter_dict,
					                                      opt->key,
					                                      opt->value,
					                                      opt->len)) {
						nm_warning ("couldn't append BYTES option '%s' to dict", opt->key);
						goto out;
					}
				}
				break;

			default:
				nm_warning ("unknown option '%s', type %d", opt->key, opt->type);
				goto out;
				break;
		}
	}

	if (!nmu_dbus_dict_close_write (&iter, &iter_dict)) {
		nm_warning ("dict close write failed!");
		goto out;
	}

	success = TRUE;

out:
	return success;
}
