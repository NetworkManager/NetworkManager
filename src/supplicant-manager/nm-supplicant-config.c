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

G_DEFINE_TYPE (NMSupplicantConfig, nm_supplicant_config, G_TYPE_OBJECT)

typedef struct {
	char *value;
	guint32 len;	
	enum OptType type;
} ConfigOption;

typedef struct
{
	char *     ifname;
	GHashTable *config;
	guint32    ap_scan;
	gboolean   dispose_has_run;
} NMSupplicantConfigPrivate;

NMSupplicantConfig *
nm_supplicant_config_new (const char *ifname)
{
	NMSupplicantConfig * scfg;

	g_return_val_if_fail (ifname != NULL, NULL);

	scfg = g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
	NM_SUPPLICANT_CONFIG_GET_PRIVATE (scfg)->ifname = g_strdup (ifname);

	return scfg;
}

static void
config_option_free (ConfigOption *opt)
{
	g_free (opt->value);
	g_slice_free (ConfigOption, opt);
}

static void
nm_supplicant_config_init (NMSupplicantConfig * self)
{
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	priv->config = g_hash_table_new_full (g_str_hash, g_str_equal,
										  (GDestroyNotify) g_free,
										  (GDestroyNotify) config_option_free);
										   
	priv->ap_scan = 1;
	priv->dispose_has_run = FALSE;
}

gboolean
nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                 const char * key,
                                 const char * value,
                                 gint32 len)
{
	NMSupplicantConfigPrivate *priv;
	ConfigOption *old_opt;
	ConfigOption *opt;
	OptType type;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

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

	old_opt = (ConfigOption *) g_hash_table_lookup (priv->config, key);
	if (old_opt) {
		nm_debug ("Key '%s' already in table.", key);
		return FALSE;
	}

	opt = g_slice_new0 (ConfigOption);
	if (opt == NULL) {
		nm_debug ("Couldn't allocate memory for new config option.");
		return FALSE;
	}

	opt->value = g_malloc0 (sizeof (char) * len);
	if (opt->value == NULL) {
		nm_debug ("Couldn't allocate memory for new config option value.");
		g_slice_free (ConfigOption, opt);
		return FALSE;
	}
	memcpy (opt->value, value, len);

	opt->len = len;
	opt->type = type;	

	g_hash_table_insert (priv->config, g_strdup (key), opt);

	return TRUE;
}

gboolean
nm_supplicant_config_remove_option (NMSupplicantConfig *self,
                                    const char * key)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	return g_hash_table_remove (NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->config, key);
}

static void
nm_supplicant_config_finalize (GObject *object)
{
	/* Complete object destruction */
	g_hash_table_destroy (NM_SUPPLICANT_CONFIG_GET_PRIVATE (object)->config);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_config_parent_class)->finalize (object);
}


static void
nm_supplicant_config_class_init (NMSupplicantConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_supplicant_config_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantConfigPrivate));
}

guint32
nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 1);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan;
}

void
nm_supplicant_config_set_ap_scan (NMSupplicantConfig * self,
                                  guint32 ap_scan)
{
	g_return_if_fail (NM_IS_SUPPLICANT_CONFIG (self));
	g_return_if_fail (ap_scan >= 0 && ap_scan <= 2);

	NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan = ap_scan;
}

static void
get_hash_cb (gpointer key, gpointer value, gpointer user_data)
{
	ConfigOption *opt = (ConfigOption *) value;
	GValue *variant;

	variant = g_slice_new0 (GValue);
	g_value_init (variant, G_TYPE_STRING);
	g_value_set_string (variant, opt->value);

	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), variant);
}

static void
destroy_hash_value (gpointer data)
{
	g_slice_free (GValue, data);
}

GHashTable *
nm_supplicant_config_get_hash (NMSupplicantConfig * self)
{
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal,
								  (GDestroyNotify) g_free,
								  destroy_hash_value);

	g_hash_table_foreach (NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->config,
						  get_hash_cb, hash);

	return hash;
}
