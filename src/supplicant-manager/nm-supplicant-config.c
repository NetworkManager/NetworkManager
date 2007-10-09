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
#include <stdlib.h>
#include <glib.h>
#include <dbus/dbus-glib.h>

#include "nm-supplicant-config.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-utils.h"
#include "dbus-dict-helpers.h"
#include "nm-setting.h"
#include "NetworkManagerUtils.h"

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
	GHashTable *config;
	guint32    ap_scan;
	gboolean   dispose_has_run;
} NMSupplicantConfigPrivate;

NMSupplicantConfig *
nm_supplicant_config_new (void)
{
	return g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
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
                                 gint32 len,
                                 gboolean secret)
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

{
char buf[255];
memset (&buf[0], 0, sizeof (buf));
memcpy (&buf[0], opt->value, opt->len > 254 ? 254 : opt->len);
nm_info ("Config: added '%s' value '%s'", key, secret ? "<omitted>" : &buf[0]);
}
	g_hash_table_insert (priv->config, g_strdup (key), opt);

	return TRUE;
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
	GArray *array;

	variant = g_slice_new0 (GValue);

	switch (opt->type) {
	case TYPE_INT:
		g_value_init (variant, G_TYPE_INT);
		g_value_set_int (variant, atoi (opt->value));
		break;
	case TYPE_BYTES:
		array = g_array_new (TRUE, TRUE, sizeof (char));
		g_array_append_vals (array, opt->value, opt->len);
		g_value_init (variant, dbus_g_type_get_collection ("GArray", G_TYPE_CHAR));
		g_value_set_boxed (variant, array);
		break;
	case TYPE_KEYWORD:
		g_value_init (variant, G_TYPE_STRING);
		g_value_set_string (variant, opt->value);
		break;
	default:
		g_slice_free (GValue, variant);
		return;
	}

	g_hash_table_insert ((GHashTable *) user_data, g_strdup (key), variant);
}

static void
destroy_hash_value (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
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

gboolean
nm_supplicant_config_add_setting_wireless (NMSupplicantConfig * self,
                                           NMSettingWireless * setting,
                                           gboolean is_broadcast)
{
	NMSupplicantConfigPrivate *priv;
	gboolean is_adhoc;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);
	
	is_adhoc = (setting->mode && !strcmp (setting->mode, "adhoc")) ? TRUE : FALSE;
	if (!is_broadcast || is_adhoc)
		priv->ap_scan = 2;

	if (!nm_supplicant_config_add_option (self, "ssid",
					      (char *) setting->ssid->data,
					      setting->ssid->len,
 	                                     FALSE)) {
		nm_warning ("Error adding SSID to supplicant config.");
		return FALSE;
	}

	if (is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "mode", "1", -1, FALSE)) {
			nm_warning ("Error adding mode to supplicant config.");
			return FALSE;
		}
	}

	/* For non-broadcast networks, we need to set "scan_ssid 1" to scan with
	 * probe request frames. However, don't try to probe Ad-Hoc networks.
	 */
	if (!is_broadcast && !is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "scan_ssid", "1", -1, FALSE))
			return FALSE;
	}

	if (setting->bssid) {
		if (!nm_supplicant_config_add_option (self, "bssid",
						      (char *) setting->bssid->data,
						      setting->bssid->len,
	 	                                     FALSE)) {
			nm_warning ("Error adding BSSID to supplicant config.");
			return FALSE;
		}
	}

	// FIXME: band & channel config items
	
	return TRUE;
}

#define ADD_STRING_VAL(field, name, ucase, unhexify, secret) \
	if (field) { \
		if (ucase) \
			value = g_ascii_strup (field, -1); \
		else if (unhexify) { \
			value = nm_utils_hexstr2bin (field, strlen (field)); \
		} else \
			value = g_strdup (field); \
		success = nm_supplicant_config_add_option (self, name, value, unhexify ? (strlen (field) / 2) : -1, secret); \
		g_free (value); \
		if (!success) { \
			nm_warning ("Error adding %s to supplicant config.", name); \
			return FALSE; \
		} \
	}

#define ADD_STRING_LIST_VAL(field, name, ucase, secret) \
	if (field) { \
		GSList *elt; \
		GString *str = g_string_new (NULL); \
		for (elt = field; elt; elt = g_slist_next (elt)) { \
			if (!str->len) { \
				g_string_append (str, elt->data); \
			} else { \
				g_string_append_c (str, ' '); \
				g_string_append (str, elt->data); \
			} \
		} \
		value = g_strdup (str->str); \
		if (ucase) \
			value = g_ascii_strup (str->str, -1); \
		g_string_free (str, TRUE); \
		success = nm_supplicant_config_add_option (self, name, value, -1, secret); \
		g_free (value); \
		if (!success) { \
			nm_warning ("Error adding %s to supplicant config.", name); \
			return FALSE; \
		} \
	}

gboolean
nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig * self,
                                                    NMSettingWirelessSecurity * setting)
{
	NMSupplicantConfigPrivate *priv;
	char * value;
	gboolean success;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	ADD_STRING_VAL (setting->key_mgmt, "key_mgmt", TRUE, FALSE, FALSE);
	ADD_STRING_VAL (setting->auth_alg, "auth_alg", TRUE, FALSE, FALSE);
	ADD_STRING_VAL (setting->proto, "proto", TRUE, FALSE, FALSE);
	ADD_STRING_VAL (setting->identity, "identity", FALSE, FALSE, FALSE);
	ADD_STRING_VAL (setting->anonymous_identity, "anonymous_identity", FALSE, FALSE, FALSE);
	ADD_STRING_VAL (setting->nai, "nai", FALSE, FALSE, FALSE);
	ADD_STRING_VAL (setting->wep_key0, "wep_key0", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->wep_key1, "wep_key1", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->wep_key2, "wep_key2", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->wep_key3, "wep_key3", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->psk, "psk", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->password, "password", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->pin, "pin", FALSE, FALSE, TRUE);
	ADD_STRING_VAL (setting->eappsk, "eappsk", FALSE, TRUE, TRUE);
	ADD_STRING_VAL (setting->private_key_passwd, "private_key_passwd", FALSE, FALSE, TRUE);
	ADD_STRING_VAL (setting->phase2_private_key_passwd, "phase2_private_key_passwd", FALSE, FALSE, TRUE);

	ADD_STRING_LIST_VAL (setting->pairwise, "pairwise", TRUE, FALSE);
	ADD_STRING_LIST_VAL (setting->group, "group", TRUE, FALSE);
	ADD_STRING_LIST_VAL (setting->eap, "eap", TRUE, FALSE);

	if (setting->wep_key0 || setting->wep_key1 || setting->wep_key2 || setting->wep_key3) {
		value = g_strdup_printf ("%d", setting->wep_tx_keyidx);
		success = nm_supplicant_config_add_option (self, "wep_tx_keyidx", value, -1, FALSE);
		g_free (value);
		if (!success) {
			nm_warning ("Error adding wep_tx_keyidx to supplicant config.");
			return FALSE;
		}
	}

	return TRUE;
}

