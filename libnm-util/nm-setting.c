/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/ether.h>

#include "nm-setting.h"
#include "nm-utils.h"

static GHashTable * nm_setting_hash (NMSetting *setting);


typedef struct {
	gboolean success;
	GHashTable *all_settings;
} VerifySettingsInfo;

static void
verify_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) value;
	VerifySettingsInfo *info = (VerifySettingsInfo *) user_data;

	if (info->success && setting->verify_fn) {
		info->success = setting->verify_fn (setting, info->all_settings);
	}
}

gboolean
nm_settings_verify (GHashTable *all_settings)
{
	gpointer p;
	VerifySettingsInfo info;

	/* First, make sure there's at least 'connection' setting */
	p = g_hash_table_lookup (all_settings, NM_SETTING_CONNECTION);
	if (!p) {
		g_warning ("'connection' setting not present.");
		return FALSE;
	}

	/* Now, run the verify function of each setting */
	info.success = TRUE;
	info.all_settings = all_settings;
	g_hash_table_foreach (all_settings, verify_one_setting, &info);

	return info.success;
}

static GHashTable *
default_setting_hash (NMSetting *setting)
{
	return nm_setting_hash (setting);
}

GHashTable *
nm_setting_to_hash (NMSetting *setting)
{
	g_return_val_if_fail (setting != NULL, NULL);
	g_return_val_if_fail (setting->hash_fn != NULL, NULL);

	return setting->hash_fn (setting);
}

gboolean
nm_setting_update_secrets (NMSetting *setting,
                           GHashTable *secrets)
{
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);

	if (setting->update_secrets_fn)
		return setting->update_secrets_fn (setting, secrets);
	return TRUE;
}

void
nm_setting_clear_secrets (NMSetting *setting)
{
	g_return_if_fail (setting != NULL);

	if (setting->clear_secrets_fn)
		return setting->clear_secrets_fn (setting);
}

GPtrArray *
nm_setting_need_secrets (NMSetting *setting)
{
	g_return_val_if_fail (setting != NULL, NULL);

	if (setting->need_secrets_fn)
		return setting->need_secrets_fn (setting);
	return NULL;
}

void
nm_setting_destroy (NMSetting *setting)
{
	char *name;

	g_return_if_fail (setting != NULL);

	name = setting->name;

	if (setting->destroy_fn)
		setting->destroy_fn (setting);

	g_free (name);
}

void
nm_setting_enumerate_values (NMSetting *setting,
                             NMSettingValueIterFn func,
                             gpointer user_data)
{
	SettingMember *m;

	g_return_if_fail (setting != NULL);
	g_return_if_fail (func != NULL);

	m = setting->_members;
	while (m->key) {
		void *val = G_STRUCT_MEMBER_P (setting, m->offset);
		(*func) (setting, m->key, m->type, val, m->secret, user_data);
		m++;
	};
}

/***********************************************************************/

/* Helper functions for converting NMSetting to hash table. */

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GHashTable *
setting_hash_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
								  destroy_gvalue);
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
boolean_to_gvalue (gboolean b)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_BOOLEAN);
	g_value_set_boolean (val, b);

	return val;
}

#if 0
static GValue *
int_to_gvalue (int i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_INT);
	g_value_set_int (val, i);

	return val;
}
#endif

static GValue *
uint_to_gvalue (guint32 i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, i);

	return val;
}

static GValue *
uint64_to_gvalue (guint64 i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT64);
	g_value_set_uint64 (val, i);

	return val;
}

#if 0
static GValue *
byte_to_gvalue (guchar c)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UCHAR);
	g_value_set_uchar (val, c);

	return val;
}
#endif

static GValue *
byte_array_to_gvalue (GByteArray *array)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

static GValue *
slist_to_gvalue (GSList *list, GType type)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, dbus_g_type_get_collection ("GSList", type));
	g_value_set_boxed (val, list);

	return val;
}

static GByteArray *
convert_array_to_byte_array (GArray *array)
{
	GByteArray *byte_array;

	byte_array = g_byte_array_sized_new (array->len);
	g_byte_array_append (byte_array, (const guint8 *) array->data, array->len);

	return byte_array;
}

static GSList *
convert_strv_to_slist (char **str)
{
	GSList *list = NULL;
	guint i = 0;

	while (str[i])
		list = g_slist_prepend (list, g_strdup (str[i++]));

	return g_slist_reverse (list);
}

static gboolean
string_in_list (const char *str, const char **valid_strings)
{
	int i;

	for (i = 0; valid_strings[i]; i++)
		if (strcmp (str, valid_strings[i]) == 0)
			break;

	return valid_strings[i] != NULL;
}

static gboolean
string_slist_validate (GSList *list, const char **valid_values)
{
	GSList *iter;

	for (iter = list; iter; iter = iter->next) {
		if (!string_in_list ((char *) iter->data, valid_values))
			return FALSE;
	}

	return TRUE;
}

/***********************************************************************/

static gboolean
nm_setting_populate_from_hash (NMSetting *setting, GHashTable *table)
{
	SettingMember *m;

	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (table != NULL, FALSE);

	m = setting->_members;
	while (m->key) {
		GValue *value;

		if (m->type == NM_S_TYPE_GVALUE_HASH) {
			GHashTable **val = (GHashTable **) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = nm_utils_gvalue_hash_dup (table);
			break;
		}

		value = (GValue *) g_hash_table_lookup (table, m->key);
		if (!value && m->required) {
			g_warning ("Missing required value '%s'.", m->key);
			return FALSE;
		} else if (!value) {
			goto next;
		}

		if ((m->type == NM_S_TYPE_STRING) && G_VALUE_HOLDS_STRING (value)) {
			char **val = (char **) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = g_strdup (g_value_get_string (value));
		} else if ((m->type == NM_S_TYPE_BOOL) && G_VALUE_HOLDS_BOOLEAN (value)) {
			gboolean *val = (gboolean *) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = g_value_get_boolean (value);
		} else if ((m->type == NM_S_TYPE_UINT32) && G_VALUE_HOLDS_UINT (value)) {
			guint32 *val = (guint32 *) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = g_value_get_uint (value);
		} else if ((m->type == NM_S_TYPE_UINT64) && G_VALUE_HOLDS_UINT64 (value)) {
			guint64 *val = (guint64 *) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = g_value_get_uint64 (value);
		} else if ((m->type == NM_S_TYPE_BYTE_ARRAY) && G_VALUE_HOLDS_BOXED (value)) {
			GByteArray **val = (GByteArray **) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));
		} else if ((m->type == NM_S_TYPE_STRING_ARRAY) && G_VALUE_HOLDS_BOXED (value)) {
			GSList **val = (GSList **) G_STRUCT_MEMBER_P (setting, m->offset);
			*val = convert_strv_to_slist ((char **) g_value_get_boxed (value));
		} 

next:
		m++;
	};

	return TRUE;
}

#define ADD_MEMBER(nmtype, ctype, key, func) \
	case nmtype: { \
		ctype* val = (ctype*) G_STRUCT_MEMBER_P (setting, m->offset); \
		if (*val || (nmtype == NM_S_TYPE_BOOL) || m->required) { \
			g_hash_table_insert (hash, (char *) key, func (*val)); \
		} \
		break; \
	}

#define ADD_MEMBER_EXTRA(nmtype, ctype, key, func, extra) \
	case nmtype: { \
		ctype* val = (ctype*) G_STRUCT_MEMBER_P (setting, m->offset); \
		if (*val || (nmtype == NM_S_TYPE_BOOL) || m->required) { \
			g_hash_table_insert (hash, (char *) key, func (*val, extra)); \
		} \
		break; \
	}

static GHashTable *
nm_setting_hash (NMSetting *setting)
{
	GHashTable *hash;
	SettingMember *m;

	g_return_val_if_fail (setting != NULL, NULL);

	hash = setting_hash_new ();

	m = setting->_members;
	while (m->key) {
		switch (m->type) {
			ADD_MEMBER(NM_S_TYPE_STRING, char *, m->key, string_to_gvalue)
			ADD_MEMBER(NM_S_TYPE_BOOL, gboolean, m->key, boolean_to_gvalue)
			ADD_MEMBER(NM_S_TYPE_UINT32, guint32, m->key, uint_to_gvalue)
			ADD_MEMBER(NM_S_TYPE_UINT64, guint64, m->key, uint64_to_gvalue)
			ADD_MEMBER(NM_S_TYPE_BYTE_ARRAY, GByteArray *, m->key, byte_array_to_gvalue)
			ADD_MEMBER_EXTRA(NM_S_TYPE_STRING_ARRAY, GSList *, m->key, slist_to_gvalue, G_TYPE_STRING)
			default:
				break;
		}
		m++;
	}
	return hash;
}

static void
default_setting_clear_secrets (NMSetting *setting)
{
	SettingMember *m;

	g_return_if_fail (setting != NULL);

	m = setting->_members;
	while (m->key) {
		if (m->secret == FALSE)
			goto next;

		switch (m->type) {
			case NM_S_TYPE_GVALUE_HASH: {
				GHashTable **val = (GHashTable **) G_STRUCT_MEMBER_P (setting, m->offset);
				g_hash_table_remove_all (*val);
				break;
			}
			case NM_S_TYPE_STRING: {
				char **val = (char **) G_STRUCT_MEMBER_P (setting, m->offset);
				g_free (*val);
				*val = NULL;
				break;
			}
			case NM_S_TYPE_BOOL: {
				gboolean *val = (gboolean *) G_STRUCT_MEMBER_P (setting, m->offset);
				*val = FALSE;
				break;
			}
			case NM_S_TYPE_UINT32: {
				guint32 *val = (guint32 *) G_STRUCT_MEMBER_P (setting, m->offset);
				*val = 0;
				break;
			}
			case NM_S_TYPE_UINT64: {
				guint64 *val = (guint64 *) G_STRUCT_MEMBER_P (setting, m->offset);
				*val = 0;
				break;
			}
			case NM_S_TYPE_BYTE_ARRAY: {
				GByteArray **val = (GByteArray **) G_STRUCT_MEMBER_P (setting, m->offset);
				g_byte_array_free (*val, TRUE);
				*val = NULL;
				break;
			}
			case NM_S_TYPE_STRING_ARRAY: {
				GSList **val = (GSList **) G_STRUCT_MEMBER_P (setting, m->offset);
				g_slist_foreach (*val, (GFunc) g_free, NULL);
				g_slist_free (*val);
				*val = NULL;
				break;
			}
		}

next:
		m++;
	}
}


/* Connection */

static gboolean
setting_connection_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingConnection *self = (NMSettingConnection *) setting;

	if (!self->name || !strlen (self->name))
		return FALSE;

	if (!self->type || !strlen (self->type))
		return FALSE;

	/* Make sure the corresponding 'type' item is present */
	if (!g_hash_table_lookup (all_settings, self->type))
		return FALSE;

	return TRUE;
}

static void
setting_connection_destroy (NMSetting *setting)
{
	NMSettingConnection *self = (NMSettingConnection *) setting;

	g_free (self->name);
	g_free (self->type);

	g_slice_free (NMSettingConnection, self);
}

static SettingMember con_table[] = {
	{ "name", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingConnection, name), TRUE, FALSE },
	{ "type", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingConnection, type), TRUE, FALSE },
	{ "autoconnect", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingConnection, autoconnect), FALSE, FALSE },
	{ "timestamp", NM_S_TYPE_UINT64, G_STRUCT_OFFSET (NMSettingConnection, timestamp), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_connection_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingConnection);

	setting->name = g_strdup (NM_SETTING_CONNECTION);
	setting->_members = con_table;
	setting->verify_fn = setting_connection_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_connection_destroy;

	return setting;
}

NMSetting *
nm_setting_connection_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_connection_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* IP4 config */

static gboolean
setting_ip4_config_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingIP4Config *self = (NMSettingIP4Config *) setting;

	if (!self->address) {
		g_warning ("address is not provided");
		return FALSE;
	}

	if (!self->netmask) {
		g_warning ("netmask is not provided");
		return FALSE;
	}

	return TRUE;
}

static void
setting_ip4_config_destroy (NMSetting *setting)
{
	NMSettingIP4Config *self = (NMSettingIP4Config *) setting;

	g_slice_free (NMSettingIP4Config, self);
}

static SettingMember ip4_config_table[] = {
	{ "manual", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingIP4Config, manual), FALSE, FALSE },
	{ "address", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingIP4Config, address), FALSE, FALSE },
	{ "netmask", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingIP4Config, netmask), FALSE, FALSE },
	{ "gateway", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingIP4Config, gateway), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_ip4_config_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingIP4Config);

	setting->name = g_strdup (NM_SETTING_IP4_CONFIG);
	setting->_members = ip4_config_table;
	setting->verify_fn = setting_ip4_config_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_ip4_config_destroy;

	return setting;
}

NMSetting *
nm_setting_ip4_config_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_ip4_config_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* Wired device */

static gboolean
setting_wired_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingWired *self = (NMSettingWired *) setting;
	const char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
	const char *valid_duplex[] = { "half", "full", NULL };

	if (self->port && !string_in_list (self->port, valid_ports)) {
		g_warning ("Invalid port");
		return FALSE;
	}

	if (self->duplex && !string_in_list (self->duplex, valid_duplex)) {
		g_warning ("Invalid duplex");
		return FALSE;
	}

	if (self->mac_address && self->mac_address->len != 6) {
		g_warning ("Invalid mac address");
		return FALSE;
	}

	return TRUE;
}

static void
setting_wired_destroy (NMSetting *setting)
{
	NMSettingWired *self = (NMSettingWired *) setting;

	g_free (self->port);
	g_free (self->duplex);

	if (self->mac_address)
		g_byte_array_free (self->mac_address, TRUE);

	g_slice_free (NMSettingWired, self);
}

static SettingMember wired_table[] = {
	{ "port", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingWired, port), FALSE, FALSE },
	{ "speed", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWired, speed), FALSE, FALSE },
	{ "duplex", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingWired, duplex), FALSE, FALSE },
	{ "auto-negotiate", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingWired, auto_negotiate), FALSE, FALSE },
	{ "mac-address", NM_S_TYPE_BYTE_ARRAY, G_STRUCT_OFFSET (NMSettingWired, mac_address), FALSE, FALSE },
	{ "mtu", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWired, mtu), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_wired_new (void)
{
	NMSetting *setting;
	NMSettingWired *s_wired;

	s_wired = g_slice_new0 (NMSettingWired);
	setting = (NMSetting *) s_wired;

	setting->name = g_strdup (NM_SETTING_WIRED);
	setting->_members = wired_table;
	setting->verify_fn = setting_wired_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_wired_destroy;

	s_wired->auto_negotiate = TRUE;

	return setting;
}

NMSetting *
nm_setting_wired_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_wired_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* Wireless device */

static gboolean
setting_wireless_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;
	const char *valid_modes[] = { "infrastructure", "adhoc", NULL };
	const char *valid_bands[] = { "a", "bg", NULL };
	GSList *iter;

	if (!self->ssid || self->ssid->len < 1 || self->ssid->len > 32) {
		g_warning ("Invalid or missing ssid");
		return FALSE;
	}

	if (self->mode && !string_in_list (self->mode, valid_modes)) {
		g_warning ("Invalid mode. Should be either 'infrastructure' or 'adhoc'");
		return FALSE;
	}

	if (self->band && !string_in_list (self->band, valid_bands)) {
		g_warning ("Invalid band. Should be either 'a' or 'bg'");
		return FALSE;
	}

	if (self->channel && !self->band) {
		g_warning ("Channel was provided without band");
		return FALSE;
	}

	if (self->channel) {
		if (!strcmp (self->band, "a")) {
			int i;
			int valid_channels[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
									 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 0 };

			for (i = 0; valid_channels[i]; i++) {
				if (self->channel == valid_channels[i])
					break;
			}

			if (valid_channels[i] == 0) {
				g_warning ("Invalid channel");
				return FALSE;
			}
		} else if (!strcmp (self->band, "bg") && self->channel > 14) {
			g_warning ("Invalid channel");
			return FALSE;
		}
	}

	if (self->bssid && self->bssid->len != 6) {
		g_warning ("Invalid bssid");
		return FALSE;
	}

	if (self->mac_address && self->mac_address->len != 6) {
		g_warning ("Invalid mac address");
		return FALSE;
	}

	for (iter = self->seen_bssids; iter; iter = iter->next) {
		struct ether_addr addr;

		if (!ether_aton_r (iter->data, &addr)) {
			g_warning ("Invalid bssid");
			return FALSE;
		}
	}

	if (self->security && !g_hash_table_lookup (all_settings, self->security)) {
		g_warning ("Invalid or missing security");
		return FALSE;
	}

	return TRUE;
}

static void
setting_wireless_destroy (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;

	g_free (self->mode);
	g_free (self->band);
	g_free (self->security);

	if (self->ssid)
		g_byte_array_free (self->ssid, TRUE);
	if (self->bssid)
		g_byte_array_free (self->bssid, TRUE);
	if (self->mac_address)
		g_byte_array_free (self->mac_address, TRUE);

	if (self->seen_bssids) {
		g_slist_foreach (self->seen_bssids, (GFunc) g_free, NULL);
		g_slist_free (self->seen_bssids);
	}
		

	g_slice_free (NMSettingWireless, self);
}

static SettingMember wireless_table[] = {
	{ "ssid", NM_S_TYPE_BYTE_ARRAY, G_STRUCT_OFFSET (NMSettingWireless, ssid), TRUE, FALSE },
	{ "mode", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingWireless, mode), FALSE, FALSE },
	{ "band", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingWireless, band), FALSE, FALSE },
	{ "channel", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWireless, channel), FALSE, FALSE },
	{ "bssid", NM_S_TYPE_BYTE_ARRAY, G_STRUCT_OFFSET (NMSettingWireless, bssid), FALSE, FALSE },
	{ "rate", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWireless, rate), FALSE, FALSE },
	{ "tx-power", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWireless, tx_power), FALSE, FALSE },
	{ "mac-address", NM_S_TYPE_BYTE_ARRAY, G_STRUCT_OFFSET (NMSettingWireless, mac_address), FALSE, FALSE },
	{ "mtu", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingWireless, mtu), FALSE, FALSE },
	{ "seen-bssids", NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingWireless, seen_bssids), FALSE, FALSE },
	{ "security", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingWireless, security), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_wireless_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingWireless);

	setting->name = g_strdup (NM_SETTING_WIRELESS);
	setting->_members = wireless_table;
	setting->verify_fn = setting_wireless_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_wireless_destroy;

	return setting;
}

NMSetting *
nm_setting_wireless_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_wireless_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* Wireless security */

static gboolean
setting_wireless_security_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;
	const char *valid_key_mgmt[] = { "none", "ieee8021x", "wpa-none", "wpa-psk", "wpa-eap", NULL };
	const char *valid_auth_algs[] = { "open", "shared", "leap", NULL };
	const char *valid_protos[] = { "wpa", "rsn", NULL };
	const char *valid_pairwise[] = { "tkip", "ccmp", NULL };
	const char *valid_groups[] = { "wep40", "wep104", "tkip", "ccmp", NULL };
	const char *valid_eap[] = { "leap", "md5", "tls", "peap", "ttls", "sim", "psk", "fast", NULL };
	const char *valid_phase1_peapver[] = { "0", "1", NULL };
	const char *valid_phase2_autheap[] = { "md5", "mschapv2", "otp", "gtc", "tls", "sim", NULL };

	if (!self->key_mgmt || !string_in_list (self->key_mgmt, valid_key_mgmt)) {
		g_warning ("Missing or invalid key management");
		return FALSE;
	}

	if (self->wep_tx_keyidx > 3) {
		g_warning ("Invalid WEP key index");
		return FALSE;
	}

	if (self->auth_alg && !string_in_list (self->auth_alg, valid_auth_algs)) {
		g_warning ("Invalid authentication algorithm");
		return FALSE;
	}

	if (self->proto && !string_slist_validate (self->proto, valid_protos)) {
		g_warning ("Invalid authentication protocol");
		return FALSE;
	}

	if (self->pairwise && !string_slist_validate (self->pairwise, valid_pairwise)) {
		g_warning ("Invalid pairwise");
		return FALSE;
	}

	if (self->group && !string_slist_validate (self->group, valid_groups)) {
		g_warning ("Invalid group");
		return FALSE;
	}

	if (self->eap && !string_slist_validate (self->eap, valid_eap)) {
		g_warning ("Invalid eap");
		return FALSE;
	}

	if (self->phase1_peapver && !string_in_list (self->phase1_peapver, valid_phase1_peapver)) {
		g_warning ("Invalid phase1 peapver");
		return FALSE;
	}

	if (self->phase1_peaplabel && strcmp (self->phase1_peaplabel, "1")) {
		g_warning ("Invalid phase1 peaplabel");
		return FALSE;
	}

	if (self->phase1_fast_provisioning && strcmp (self->phase1_fast_provisioning, "1")) {
		g_warning ("Invalid phase1 fast provisioning");
		return FALSE;
	}

	if (self->phase2_auth && strcmp (self->phase2_auth, "mschapv2")) {
		g_warning ("Invalid phase2 authentication");
		return FALSE;
	}

	if (self->phase2_autheap && !string_in_list (self->phase2_autheap, valid_phase2_autheap)) {
		g_warning ("Invalid phase2 autheap");
		return FALSE;
	}

	/* FIXME: finish */

	return TRUE;
}

static void
setting_wireless_security_destroy (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;

	/* Strings first. g_free() already checks for NULLs so we don't have to */

	g_free (self->key_mgmt);
	g_free (self->auth_alg);
	g_free (self->identity);
	g_free (self->anonymous_identity);
	g_free (self->ca_path);
	g_free (self->phase1_peapver);
	g_free (self->phase1_peaplabel);
	g_free (self->phase1_fast_provisioning);
	g_free (self->phase2_auth);
	g_free (self->phase2_autheap);
	g_free (self->phase2_ca_path);
	g_free (self->nai);
	g_free (self->wep_key0);
	g_free (self->wep_key1);
	g_free (self->wep_key2);
	g_free (self->wep_key3);
	g_free (self->psk);
	g_free (self->password);
	g_free (self->pin);
	g_free (self->eappsk);
	g_free (self->private_key_passwd);
	g_free (self->phase2_private_key_passwd);

	if (self->proto) {
		g_slist_foreach (self->proto, (GFunc) g_free, NULL);
		g_slist_free (self->proto);
	}

	if (self->pairwise) {
		g_slist_foreach (self->pairwise, (GFunc) g_free, NULL);
		g_slist_free (self->pairwise);
	}

	if (self->group) {
		g_slist_foreach (self->group, (GFunc) g_free, NULL);
		g_slist_free (self->group);
	}

	if (self->eap) {
		g_slist_foreach (self->eap, (GFunc) g_free, NULL);
		g_slist_free (self->eap);
	}

	if (self->ca_cert)
		g_byte_array_free (self->ca_cert, TRUE);
	if (self->client_cert)
		g_byte_array_free (self->client_cert, TRUE);
	if (self->private_key)
		g_byte_array_free (self->private_key, TRUE);
	if (self->phase2_ca_cert)
		g_byte_array_free (self->phase2_ca_cert, TRUE);
	if (self->phase2_client_cert)
		g_byte_array_free (self->phase2_client_cert, TRUE);
	if (self->phase2_private_key)
		g_byte_array_free (self->phase2_private_key, TRUE);

	g_slice_free (NMSettingWirelessSecurity, self);
}

static gboolean
setting_wireless_security_update_secrets (NMSetting *setting,
                                          GHashTable *secrets)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;
	SettingMember *m;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);

	m = setting->_members;
	while (m->key) {
		GValue *value;

		if (m->secret == FALSE)
			goto next;

		value = (GValue *) g_hash_table_lookup (secrets, m->key);
		if (value && G_VALUE_HOLDS_STRING (value)) {
			char **val = (char **) G_STRUCT_MEMBER_P (setting, m->offset);
			g_free (*val);
			*val = g_strdup (g_value_get_string (value));
		}

next:
		m++;
	}

	return TRUE;
}

static gboolean
verify_wep_key (const char *key)
{
	int keylen, i;

	if (!key)
		return FALSE;

	keylen = strlen (key);
	if (keylen != 10 && keylen != 26)
		return FALSE;

	for (i = 0; i < keylen; i++) {
		if (!isxdigit (key[i]))
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify_wpa_psk (const char *psk)
{
	int psklen, i;

	if (!psk)
		return FALSE;

	psklen = strlen (psk);
	if (psklen != 64)
		return FALSE;

	for (i = 0; i < psklen; i++) {
		if (!isxdigit (psk[i]))
			return FALSE;
	}

	return TRUE;
}

static GPtrArray *
setting_wireless_security_need_secrets (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;
	GPtrArray *secrets;

	secrets = g_ptr_array_sized_new (4);
	if (!secrets) {
		g_warning ("Not enough memory to create required secrets array.");
		return NULL;
	}

	g_assert (self->key_mgmt);

	/* Static WEP */
	// FIXME: check key length too
	if (strcmp (self->key_mgmt, "none") == 0) {
		if (!verify_wep_key (self->wep_key0)) {
			g_ptr_array_add (secrets, "wep-key0");
			return secrets;
		}
		if (self->wep_tx_keyidx == 1 && !verify_wep_key (self->wep_key1)) {
			g_ptr_array_add (secrets, "wep-key1");
			return secrets;
		}
		if (self->wep_tx_keyidx == 2 && !verify_wep_key (self->wep_key2)) {
			g_ptr_array_add (secrets, "wep-key2");
			return secrets;
		}
		if (self->wep_tx_keyidx == 3 && !verify_wep_key (self->wep_key3)) {
			g_ptr_array_add (secrets, "wep-key3");
			return secrets;
		}
		goto no_secrets;
	}

	if (   (strcmp (self->key_mgmt, "wpa-none") == 0)
	    || (strcmp (self->key_mgmt, "wpa-psk") == 0)) {
		if (!verify_wpa_psk (self->psk)) {
			g_ptr_array_add (secrets, "psk");
			return secrets;
		}
		goto no_secrets;
	}

	if (strcmp (self->key_mgmt, "wpa-eap") == 0) {
		// FIXME: implement
		goto no_secrets;
	}

	return secrets;

no_secrets:
	if (secrets)
		g_ptr_array_free (secrets, TRUE);
	return NULL;
}

static SettingMember wireless_sec_table[] = {
	{ "key-mgmt",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, key_mgmt),                  TRUE, FALSE },
	{ "wep-tx-keyidx",             NM_S_TYPE_UINT32,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, wep_tx_keyidx),             FALSE, FALSE },
	{ "auth-alg",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, auth_alg),                  FALSE, FALSE },
	{ "proto",                     NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingWirelessSecurity, proto),                     FALSE, FALSE },
	{ "pairwise",                  NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingWirelessSecurity, pairwise),                  FALSE, FALSE },
	{ "group",                     NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingWirelessSecurity, group),                     FALSE, FALSE },
	{ "eap",                       NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingWirelessSecurity, eap),                       FALSE, FALSE },
	{ "identity",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, identity),                  FALSE, FALSE },
	{ "anonymous-identity",        NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, anonymous_identity),        FALSE, FALSE },
	{ "ca-cert",                   NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, ca_cert),                   FALSE, FALSE },
	{ "ca-path",                   NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, ca_path),                   FALSE, FALSE },
	{ "client-cert",               NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, client_cert),               FALSE, FALSE },
	{ "private-key",               NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, private_key),               FALSE, FALSE },
	{ "phase1-peapver",            NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase1_peapver),            FALSE, FALSE },
	{ "phase1-peaplabel",          NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase1_peaplabel),          FALSE, FALSE },
	{ "phase1-fast-provisioning",  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase1_fast_provisioning),  FALSE, FALSE },
	{ "phase2-auth",               NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_auth),               FALSE, FALSE },
	{ "phase2-autheap",            NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_autheap),            FALSE, FALSE },
	{ "phase2-ca-cert",            NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_ca_cert),            FALSE, FALSE },
	{ "phase2-ca-path",            NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_ca_path),            FALSE, FALSE },
	{ "phase2-client-cert",        NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_client_cert),        FALSE, FALSE },
	{ "phase2-private-key",        NM_S_TYPE_BYTE_ARRAY,   G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_private_key),        FALSE, FALSE },
	{ "nai",                       NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, nai),                       FALSE, FALSE },
	{ "wep-key0",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, wep_key0),                  FALSE, TRUE },
	{ "wep-key1",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, wep_key1),                  FALSE, TRUE },
	{ "wep-key2",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, wep_key2),                  FALSE, TRUE },
	{ "wep-key3",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, wep_key3),                  FALSE, TRUE },
	{ "psk",                       NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, psk),                       FALSE, TRUE },
	{ "password",                  NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, password),                  FALSE, TRUE },
	{ "pin",                       NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, pin),                       FALSE, TRUE },
	{ "eappsk",                    NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, eappsk),                    FALSE, TRUE },
	{ "private-key-passwd",        NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, private_key_passwd),        FALSE, TRUE },
	{ "phase2-private-key-passwd", NM_S_TYPE_STRING,       G_STRUCT_OFFSET (NMSettingWirelessSecurity, phase2_private_key_passwd), FALSE, TRUE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_wireless_security_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingWirelessSecurity);

	setting->name = g_strdup (NM_SETTING_WIRELESS_SECURITY);
	setting->_members = wireless_sec_table;
	setting->verify_fn = setting_wireless_security_verify;
	setting->hash_fn = default_setting_hash;
	setting->update_secrets_fn = setting_wireless_security_update_secrets;
	setting->need_secrets_fn = setting_wireless_security_need_secrets;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_wireless_security_destroy;

	return setting;
}

NMSetting *
nm_setting_wireless_security_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_wireless_security_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* PPP */

static gboolean
setting_ppp_verify (NMSetting *setting, GHashTable *all_settings)
{
	/* FIXME: Do we even want this or can we just let pppd evaluate the options? */
	return TRUE;
}

static void
setting_ppp_destroy (NMSetting *setting)
{
	NMSettingPPP *self = (NMSettingPPP *) setting;

	g_slice_free (NMSettingPPP, self);
}

static SettingMember ppp_table[] = {
	{ "noauth", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, noauth), FALSE, FALSE },
	{ "refuse-eap", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, refuse_eap), FALSE, FALSE },
	{ "refuse-chap", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, refuse_chap), FALSE, FALSE },
	{ "refuse-mschap", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, refuse_mschap), FALSE, FALSE },
	{ "nobsdcomp", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, nobsdcomp), FALSE, FALSE },
	{ "nodeflate", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, nodeflate), FALSE, FALSE },
	{ "require-mppe", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, require_mppe), FALSE, FALSE },
	{ "require-mppe-128", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, require_mppe_128), FALSE, FALSE },
	{ "mppe-stateful", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, mppe_stateful), FALSE, FALSE },
	{ "require-mppc", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, require_mppc), FALSE, FALSE },
	{ "crtscts", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, crtscts), FALSE, FALSE },
	{ "usepeerdns", NM_S_TYPE_BOOL, G_STRUCT_OFFSET (NMSettingPPP, usepeerdns), FALSE, FALSE },
	{ "baud", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingPPP, baud), FALSE, FALSE },
	{ "mru", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingPPP, mru), FALSE, FALSE },
	{ "mtu", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingPPP, mtu), FALSE, FALSE },
	{ "lcp-echo-failure", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingPPP, lcp_echo_failure), FALSE, FALSE },
	{ "lcp-echo-interval", NM_S_TYPE_UINT32, G_STRUCT_OFFSET (NMSettingPPP, lcp_echo_interval), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_ppp_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingPPP);

	setting->name = g_strdup (NM_SETTING_PPP);
	setting->_members = ppp_table;
	setting->verify_fn = setting_ppp_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_ppp_destroy;

	return setting;
}

NMSetting *
nm_setting_ppp_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_ppp_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* vpn setting */

static gboolean
setting_vpn_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingVPN *self = (NMSettingVPN *) setting;

	if (!self->service_type || !strlen (self->service_type))
		return FALSE;

	/* default username can be NULL, but can't be zero-length */
	if (self->user_name && !strlen (self->user_name))
		return FALSE;

	return TRUE;
}

static void
setting_vpn_destroy (NMSetting *setting)
{
	NMSettingVPN *self = (NMSettingVPN *) setting;

	g_free (self->service_type);
	g_free (self->user_name);

	if (self->routes) {
		g_slist_foreach (self->routes, (GFunc) g_free, NULL);
		g_slist_free (self->routes);
	}

	g_slice_free (NMSettingVPN, self);
}

static SettingMember vpn_table[] = {
	{ "service_type", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingVPN, service_type), TRUE, FALSE },
	{ "user_name", NM_S_TYPE_STRING, G_STRUCT_OFFSET (NMSettingVPN, user_name), FALSE, FALSE },
	{ "routes", NM_S_TYPE_STRING_ARRAY, G_STRUCT_OFFSET (NMSettingVPN, routes), FALSE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_vpn_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingVPN);

	setting->name = g_strdup (NM_SETTING_VPN);
	setting->_members = vpn_table;
	setting->verify_fn = setting_vpn_verify;
	setting->hash_fn = default_setting_hash;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_vpn_destroy;

	return setting;
}

NMSetting *
nm_setting_vpn_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_vpn_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}

/* vpn-properties setting */

static gboolean
setting_vpn_properties_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingVPNProperties *self = (NMSettingVPNProperties *) setting;

	if (!self->data)
		return FALSE;

	/* FIXME: actually check the data as well */

	return TRUE;
}

static GHashTable *
setting_vpn_properties_hash (NMSetting *setting)
{
	NMSettingVPNProperties *self = (NMSettingVPNProperties *) setting;

	g_return_val_if_fail (self->data != NULL, NULL);

	return nm_utils_gvalue_hash_dup (self->data);
}

static void
setting_vpn_properties_destroy (NMSetting *setting)
{
	NMSettingVPNProperties *self = (NMSettingVPNProperties *) setting;

	g_hash_table_destroy (self->data);
	g_slice_free (NMSettingVPNProperties, self);
}

static void
property_value_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, data);
}

static void
add_one_secret (gpointer key, gpointer value, gpointer user_data)
{
	NMSettingVPNProperties *self = (NMSettingVPNProperties *) user_data;
	GValue * new_value;

	if (!value || !G_VALUE_HOLDS_STRING (value))
		return;

	new_value = g_slice_new0 (GValue);
	if (!new_value)
		return;

	g_value_init (new_value, G_TYPE_STRING);
	g_value_copy (value, new_value);
	g_hash_table_insert (self->data, g_strdup (key), new_value);
}

static gboolean
setting_vpn_properties_update_secrets (NMSetting *setting,
                                       GHashTable *secrets)
{
	NMSettingVPNProperties *self = (NMSettingVPNProperties *) setting;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (secrets != NULL, FALSE);

	g_hash_table_foreach (secrets, add_one_secret, self);
	return TRUE;
}

static SettingMember vpn_properties_table[] = {
	{ "data", NM_S_TYPE_GVALUE_HASH, G_STRUCT_OFFSET (NMSettingVPNProperties, data), TRUE, FALSE },
	{ NULL, 0, 0 },
};

NMSetting *
nm_setting_vpn_properties_new (void)
{
	NMSetting *setting;
	NMSettingVPNProperties *s_vpn_props;

	setting = (NMSetting *) g_slice_new0 (NMSettingVPNProperties);

	setting->name = g_strdup (NM_SETTING_VPN_PROPERTIES);
	setting->_members = vpn_properties_table;
	setting->verify_fn = setting_vpn_properties_verify;
	setting->hash_fn = setting_vpn_properties_hash;
	setting->update_secrets_fn = setting_vpn_properties_update_secrets;
	setting->clear_secrets_fn = default_setting_clear_secrets;
	setting->destroy_fn = setting_vpn_properties_destroy;

	s_vpn_props = (NMSettingVPNProperties *) setting;
	s_vpn_props->data = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           (GDestroyNotify) g_free,
	                                           property_value_destroy);

	return setting;
}

NMSetting *
nm_setting_vpn_properties_new_from_hash (GHashTable *hash)
{
	NMSetting *setting;

	g_return_val_if_fail (hash != NULL, NULL);

	setting = nm_setting_vpn_properties_new ();
	if (!nm_setting_populate_from_hash (setting, hash)) {
		nm_setting_destroy (setting);
		return NULL;
	}

	return setting;
}
