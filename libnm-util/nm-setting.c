/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-setting.h"

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
	p = g_hash_table_lookup (all_settings, "connection");
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

GHashTable *
nm_setting_to_hash (NMSetting *setting)
{
	g_return_val_if_fail (setting != NULL, NULL);
	g_return_val_if_fail (setting->hash_fn != NULL, NULL);

	return setting->hash_fn (setting);
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

static GValue *
int_to_gvalue (int i)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_INT);
	g_value_set_int (val, i);

	return val;
}

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
byte_to_gvalue (guchar c)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UCHAR);
	g_value_set_uchar (val, c);

	return val;
}

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
		list = g_slist_prepend (list, str[i++]);

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

/* Connection */

static gboolean
setting_connection_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingConnection *self = (NMSettingConnection *) setting;

	/* Make sure the corresponding 'devtype' item is present */
	if (!g_hash_table_lookup (all_settings, self->devtype))
		return FALSE;

	return TRUE;
}

static GHashTable *
setting_connection_hash (NMSetting *setting)
{
	NMSettingConnection *self = (NMSettingConnection *) setting;
	GHashTable *hash;

	g_return_val_if_fail (self->name != NULL, NULL);
	g_return_val_if_fail (self->devtype != NULL, NULL);

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "name", string_to_gvalue (self->name));
	g_hash_table_insert (hash, "devtype", string_to_gvalue (self->devtype));
	// FIXME: autoconnect is optional, need to differentiate between TRUE/FALSE
	// and "not present"
	g_hash_table_insert (hash, "autoconnect", boolean_to_gvalue (self->autoconnect));

	return hash;
}

static void
setting_connection_destroy (NMSetting *setting)
{
	NMSettingConnection *self = (NMSettingConnection *) setting;

	g_free (self->name);
	g_free (self->devtype);

	g_slice_free (NMSettingConnection, self);
}

NMSetting *
nm_setting_connection_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingConnection);

	setting->name = g_strdup ("connection");
	setting->verify_fn = setting_connection_verify;
	setting->hash_fn = setting_connection_hash;
	setting->destroy_fn = setting_connection_destroy;

	return setting;
}

NMSetting *
nm_setting_connection_new_from_hash (GHashTable *settings)
{
	NMSettingConnection *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_connection_new ();
	self = (NMSettingConnection *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "name");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->name = g_strdup (g_value_get_string (value));
	else {
		g_warning ("Missing or invalid connection name");
		goto err;
	}

	value = (GValue *) g_hash_table_lookup (settings, "devtype");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->devtype = g_strdup (g_value_get_string (value));
	else {
		g_warning ("Missing or invalid devtype");
		goto err;
	}

	value = (GValue *) g_hash_table_lookup (settings, "autoconnect");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->autoconnect = g_value_get_boolean (value);

	return setting;

 err:
	setting_connection_destroy (setting);

	return NULL;
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

static GHashTable *
setting_ip4_config_hash (NMSetting *setting)
{
	NMSettingIP4Config *self = (NMSettingIP4Config *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "manual", boolean_to_gvalue (self->manual));
	g_hash_table_insert (hash, "address", uint_to_gvalue (self->address));
	g_hash_table_insert (hash, "netmask", uint_to_gvalue (self->netmask));
	g_hash_table_insert (hash, "gateway", uint_to_gvalue (self->gateway));

	return hash;
}

static void
setting_ip4_config_destroy (NMSetting *setting)
{
	NMSettingIP4Config *self = (NMSettingIP4Config *) setting;

	g_slice_free (NMSettingIP4Config, self);
}

NMSetting *
nm_setting_ip4_config_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingIP4Config);

	setting->name = g_strdup ("ipv4");
	setting->verify_fn = setting_ip4_config_verify;
	setting->hash_fn = setting_ip4_config_hash;
	setting->destroy_fn = setting_ip4_config_destroy;

	return setting;
}

NMSetting *
nm_setting_ip4_config_new_from_hash (GHashTable *settings)
{
	NMSettingIP4Config*self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_ip4_config_new ();
	self = (NMSettingIP4Config *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "manual");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->manual = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "address");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->address = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "netmask");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->netmask = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "gateway");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->gateway = g_value_get_uint (value);

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

static GHashTable *
setting_wired_hash (NMSetting *setting)
{
	NMSettingWired *self = (NMSettingWired *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "port", string_to_gvalue (self->port));
	g_hash_table_insert (hash, "speed", uint_to_gvalue (self->speed));
	g_hash_table_insert (hash, "duplex", string_to_gvalue (self->duplex));
	g_hash_table_insert (hash, "auto-negotiate", boolean_to_gvalue (self->auto_negotiate));
	g_hash_table_insert (hash, "mac-address", byte_array_to_gvalue (self->mac_address));
	g_hash_table_insert (hash, "mtu", uint_to_gvalue (self->mtu));

	return hash;
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

NMSetting *
nm_setting_wired_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingWired);

	setting->name = g_strdup ("802-3-ethernet");
	setting->verify_fn = setting_wired_verify;
	setting->hash_fn = setting_wired_hash;
	setting->destroy_fn = setting_wired_destroy;

	return setting;
}

NMSetting *
nm_setting_wired_new_from_hash (GHashTable *settings)
{
	NMSettingWired *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_wired_new ();
	self = (NMSettingWired *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "port");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->port = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "speed");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->speed = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "duplex");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->duplex = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "auto-negotiate");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->auto_negotiate = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "mac-address");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->mac_address = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "mtu");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->mtu = g_value_get_uint (value);

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
		GByteArray *bssid = (GByteArray *) iter->data;
		if (bssid->len != 6) {
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

static GHashTable *
setting_wireless_hash (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;
	GHashTable *hash;

	g_return_val_if_fail (self->ssid != NULL, NULL);

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "ssid", byte_array_to_gvalue (self->ssid));

	if (self->mode)
		g_hash_table_insert (hash, "mode", string_to_gvalue (self->mode));
	if (self->band)
		g_hash_table_insert (hash, "band", string_to_gvalue (self->band));
	if (self->channel)
		g_hash_table_insert (hash, "channel", uint_to_gvalue (self->channel));
	if (self->bssid)
		g_hash_table_insert (hash, "bssid", byte_array_to_gvalue (self->bssid));
	if (self->rate)
		g_hash_table_insert (hash, "channel", uint_to_gvalue (self->rate));
	if (self->tx_power)
		g_hash_table_insert (hash, "tx-power", uint_to_gvalue (self->tx_power));
	if (self->mac_address)
		g_hash_table_insert (hash, "mac-address", byte_array_to_gvalue (self->mac_address));
	if (self->mtu)
		g_hash_table_insert (hash, "mtu", uint_to_gvalue (self->mtu));

	if (self->seen_bssids) {
		GArray *seen_bssids;
		GValue *seen_bssids_value;
		GSList *iter;

		seen_bssids = g_array_new (FALSE, FALSE, sizeof (gint));
		for (iter = self->seen_bssids; iter; iter = iter->next)
			g_array_append_val (seen_bssids, iter->data);

		seen_bssids_value = g_slice_new0 (GValue);
		g_value_init (seen_bssids_value, dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_UCHAR_ARRAY));
		g_value_set_boxed (seen_bssids_value, seen_bssids);

		g_hash_table_insert (hash, "seen-bssids", seen_bssids_value);
	}

	if (self->security)
		g_hash_table_insert (hash, "security", string_to_gvalue (self->security));

	return hash;
}


static void
setting_wireless_destroy (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;
	GSList *iter;

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
		for (iter = self->seen_bssids; iter; iter = iter->next)
			g_byte_array_free ((GByteArray *) iter->data, TRUE);
		g_slist_free (self->seen_bssids);
	}
		

	g_slice_free (NMSettingWireless, self);
}

NMSetting *
nm_setting_wireless_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingWireless);

	setting->name = g_strdup ("802-11-wireless");
	setting->verify_fn = setting_wireless_verify;
	setting->hash_fn = setting_wireless_hash;
	setting->destroy_fn = setting_wireless_destroy;

	return setting;
}

NMSetting *
nm_setting_wireless_new_from_hash (GHashTable *settings)
{
	NMSettingWireless *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_wireless_new ();
	self = (NMSettingWireless *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "ssid");
	if (value && G_VALUE_HOLDS_BOXED (value)) {
		GArray *array;

		array = (GArray *) g_value_get_boxed (value);

		self->ssid = g_byte_array_sized_new (array->len);
		g_byte_array_append (self->ssid, (const guint8 *) array->data, array->len);
	}else {
		g_warning ("Missing or invalid ssid");
		goto err;
	}

	value = (GValue *) g_hash_table_lookup (settings, "mode");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->mode = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "band");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->band = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "channel");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->channel = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "bssid");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->bssid = (GByteArray *) g_value_get_boxed (value);

	value = (GValue *) g_hash_table_lookup (settings, "rate");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->rate = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "tx-power");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->tx_power = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "mac-address");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->mac_address = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "mtu");
	if (value && G_VALUE_HOLDS_UINT (value))
		self->mtu = g_value_get_uint (value);

	value = (GValue *) g_hash_table_lookup (settings, "seen-bssids");
	if (value) {
		int i;
		GPtrArray *ptr_array;

		ptr_array = (GPtrArray *) g_value_get_boxed (value);
		for (i = 0; i < ptr_array->len; i++) {
			self->seen_bssids = g_slist_prepend (self->seen_bssids,
												 convert_array_to_byte_array ((GArray *) g_ptr_array_index (ptr_array, i)));
		}

		self->seen_bssids = g_slist_reverse (self->seen_bssids);
	}

	value = (GValue *) g_hash_table_lookup (settings, "security");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->security = g_strdup (g_value_get_string (value));

	return setting;

 err:
	setting_wireless_destroy (setting);

	return NULL;
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

	if (self->key_mgmt && !string_in_list (self->key_mgmt, valid_key_mgmt)) {
		g_warning ("Invalid key management");
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

	if (self->proto && !string_in_list (self->proto, valid_protos)) {
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

static GHashTable *
setting_wireless_security_hash (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();

	if (self->key_mgmt)
		g_hash_table_insert (hash, "key-mgmt", string_to_gvalue (self->key_mgmt));
	if (self->wep_tx_keyidx)
 		g_hash_table_insert (hash, "wep-tx-keyidx", byte_to_gvalue (self->wep_tx_keyidx));
	if (self->auth_alg)
		g_hash_table_insert (hash, "auth-alg", string_to_gvalue (self->auth_alg));
	if (self->proto)
		g_hash_table_insert (hash, "proto", string_to_gvalue (self->proto));
	if (self->pairwise)
		g_hash_table_insert (hash, "pairwise", slist_to_gvalue (self->pairwise, G_TYPE_STRING));
	if (self->group)
		g_hash_table_insert (hash, "group", slist_to_gvalue (self->group, G_TYPE_STRING));
	if (self->eap)
		g_hash_table_insert (hash, "eap", slist_to_gvalue (self->eap, G_TYPE_STRING));
	if (self->identity)
		g_hash_table_insert (hash, "identity", string_to_gvalue (self->identity));
	if (self->anonymous_identity)
		g_hash_table_insert (hash, "anonymous-identity", string_to_gvalue (self->anonymous_identity));
	if (self->ca_cert)
		g_hash_table_insert (hash, "ca-cert", byte_array_to_gvalue (self->ca_cert));
	if (self->ca_path)
		g_hash_table_insert (hash, "ca-path", string_to_gvalue (self->ca_path));
	if (self->client_cert)
		g_hash_table_insert (hash, "client-cert", byte_array_to_gvalue (self->client_cert));
	if (self->private_key)
		g_hash_table_insert (hash, "private-key", byte_array_to_gvalue (self->private_key));
	if (self->phase1_peapver)
		g_hash_table_insert (hash, "phase1-peapver", string_to_gvalue (self->phase1_peapver));
	if (self->phase1_peaplabel)
		g_hash_table_insert (hash, "phase1-peaplabel", string_to_gvalue (self->phase1_peaplabel));
	if (self->phase1_fast_provisioning)
		g_hash_table_insert (hash, "phase1-fast-provisioning", string_to_gvalue (self->phase1_fast_provisioning));
	if (self->phase2_auth)
		g_hash_table_insert (hash, "phase2-auth", string_to_gvalue (self->phase2_auth));
	if (self->phase2_autheap)
		g_hash_table_insert (hash, "phase2-autheap", string_to_gvalue (self->phase2_autheap));
	if (self->phase2_ca_cert)
		g_hash_table_insert (hash, "phase2-ca-cert", byte_array_to_gvalue (self->phase2_ca_cert));
	if (self->phase2_ca_path)
		g_hash_table_insert (hash, "phase2-ca-path", string_to_gvalue (self->phase2_ca_path));
	if (self->phase2_client_cert)
		g_hash_table_insert (hash, "phase2-client-cert", byte_array_to_gvalue (self->phase2_client_cert));
	if (self->phase2_private_key)
		g_hash_table_insert (hash, "phase2-private-key", byte_array_to_gvalue (self->phase2_private_key));
	if (self->nai)
		g_hash_table_insert (hash, "nai", string_to_gvalue (self->nai));
	if (self->wep_key0)
		g_hash_table_insert (hash, "wep_key0", string_to_gvalue (self->wep_key0));
	if (self->wep_key1)
		g_hash_table_insert (hash, "wep_key1", string_to_gvalue (self->wep_key1));
	if (self->wep_key2)
		g_hash_table_insert (hash, "wep_key2", string_to_gvalue (self->wep_key2));
	if (self->wep_key3)
		g_hash_table_insert (hash, "wep_key3", string_to_gvalue (self->wep_key3));
	if (self->psk)
		g_hash_table_insert (hash, "psk", string_to_gvalue (self->psk));
	if (self->password)
		g_hash_table_insert (hash, "password", string_to_gvalue (self->password));
	if (self->pin)
		g_hash_table_insert (hash, "pin", string_to_gvalue (self->pin));
	if (self->eappsk)
		g_hash_table_insert (hash, "eappsk", string_to_gvalue (self->eappsk));
	if (self->private_key_passwd)
		g_hash_table_insert (hash, "private-key-passwd", string_to_gvalue (self->private_key_passwd));
	if (self->phase2_private_key_passwd)
		g_hash_table_insert (hash, "phase2-private-key-passwd", string_to_gvalue (self->phase2_private_key_passwd));

	return hash;
}


static void
setting_wireless_security_destroy (NMSetting *setting)
{
	NMSettingWirelessSecurity *self = (NMSettingWirelessSecurity *) setting;

	/* Strings first. g_free() already checks for NULLs so we don't have to */

	g_free (self->key_mgmt);
	g_free (self->auth_alg);
	g_free (self->proto);
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

NMSetting *
nm_setting_wireless_security_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingWirelessSecurity);

	setting->name = g_strdup ("802-11-wireless-security");
	setting->verify_fn = setting_wireless_security_verify;
	setting->hash_fn = setting_wireless_security_hash;
	setting->destroy_fn = setting_wireless_security_destroy;

	return setting;
}

NMSetting *
nm_setting_wireless_security_new_from_hash (GHashTable *settings)
{
	NMSettingWirelessSecurity *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_wireless_security_new ();
	self = (NMSettingWirelessSecurity *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "key-mgmt");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->key_mgmt = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "wep-tx-keyidx");
	if (value && G_VALUE_HOLDS_UCHAR (value))
		self->wep_tx_keyidx = g_value_get_uchar (value);

	value = (GValue *) g_hash_table_lookup (settings, "auth-alg");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->auth_alg = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "proto");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->proto = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "pairwise");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->pairwise = convert_strv_to_slist ((char **) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "group");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->group = convert_strv_to_slist ((char **) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "eap");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->eap = convert_strv_to_slist ((char **) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "identity");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->identity = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "anonymous-identity");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->anonymous_identity = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "ca-cert");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->ca_cert = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "ca-path");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->ca_path = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "client-cert");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->client_cert = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "private-key");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->private_key = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase1-peapver");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase1_peapver = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase1-peaplabel");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase1_peaplabel = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase1-fast-provisioning");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase1_fast_provisioning = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-auth");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase2_auth = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-autheap");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase2_autheap = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-ca-cert");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->phase2_ca_cert = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-ca-path");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase2_ca_path = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-client-cert");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->phase2_client_cert = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-private-key");
	if (value && G_VALUE_HOLDS_BOXED (value))
		self->phase2_private_key = convert_array_to_byte_array ((GArray *) g_value_get_boxed (value));

	value = (GValue *) g_hash_table_lookup (settings, "nai");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->nai = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "wep_key0");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->wep_key0 = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "wep_key1");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->wep_key1 = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "wep_key2");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->wep_key2 = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "wep_key3");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->wep_key3 = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "psk");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->psk = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "password");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->password = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "pin");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->pin = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "eappsk");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->eappsk = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "private-key-passwd");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->private_key_passwd = g_strdup (g_value_get_string (value));

	value = (GValue *) g_hash_table_lookup (settings, "phase2-private-key-passwd");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->phase2_private_key_passwd = g_strdup (g_value_get_string (value));

	return setting;
}

/* PPP */

static gboolean
setting_ppp_verify (NMSetting *setting, GHashTable *all_settings)
{
	/* FIXME: Do we even want this or can we just let pppd evaluate the options? */
	return TRUE;
}

static GHashTable *
setting_ppp_hash (NMSetting *setting)
{
	NMSettingPPP *self = (NMSettingPPP *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();

	g_hash_table_insert (hash, "noauth",           boolean_to_gvalue (self->noauth));
	g_hash_table_insert (hash, "refuse-eap",       boolean_to_gvalue (self->refuse_eap));
	g_hash_table_insert (hash, "refuse-chap",      boolean_to_gvalue (self->refuse_chap));
	g_hash_table_insert (hash, "refuse-mschap",    boolean_to_gvalue (self->refuse_mschap));
	g_hash_table_insert (hash, "nobsdcomp",        boolean_to_gvalue (self->nobsdcomp));
	g_hash_table_insert (hash, "nodeflate",        boolean_to_gvalue (self->nodeflate));
	g_hash_table_insert (hash, "require-mppe",     boolean_to_gvalue (self->require_mppe));
	g_hash_table_insert (hash, "require-mppe-128", boolean_to_gvalue (self->require_mppe_128));
	g_hash_table_insert (hash, "mppe-stateful",    boolean_to_gvalue (self->mppe_stateful));
	g_hash_table_insert (hash, "require-mppc",     boolean_to_gvalue (self->require_mppc));
	g_hash_table_insert (hash, "crtscts",          boolean_to_gvalue (self->crtscts));
	g_hash_table_insert (hash, "usepeerdns",       boolean_to_gvalue (self->usepeerdns));

	g_hash_table_insert (hash, "baud",              int_to_gvalue (self->baud));
	g_hash_table_insert (hash, "mru",               int_to_gvalue (self->mru));
	g_hash_table_insert (hash, "mtu",               int_to_gvalue (self->mtu));
	g_hash_table_insert (hash, "lcp-echo-failure",  int_to_gvalue (self->lcp_echo_failure));
	g_hash_table_insert (hash, "lcp-echo-interval", int_to_gvalue (self->lcp_echo_interval));

	return hash;
}


static void
setting_ppp_destroy (NMSetting *setting)
{
	NMSettingPPP *self = (NMSettingPPP *) setting;

	g_slice_free (NMSettingPPP, self);
}

NMSetting *
nm_setting_ppp_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingPPP);

	setting->name = g_strdup ("ppp");
	setting->verify_fn = setting_ppp_verify;
	setting->hash_fn = setting_ppp_hash;
	setting->destroy_fn = setting_ppp_destroy;

	return setting;
}

NMSetting *
nm_setting_ppp_new_from_hash (GHashTable *settings)
{
	NMSettingPPP *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_ppp_new ();
	self = (NMSettingPPP *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "noauth");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->noauth = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "refuse-eap");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->refuse_eap = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "refuse-chap");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->refuse_chap = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "refuse-mschap");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->refuse_mschap = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "nobsdcomp");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->nobsdcomp = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "nodeflate");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->nodeflate = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "require-mppe");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->require_mppe = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "require-mppe-128");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->require_mppe_128 = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "mppe-stateful");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->mppe_stateful = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "require-mppc");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->require_mppc = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "crtscts");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->crtscts = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "usepeerdns");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		self->usepeerdns = g_value_get_boolean (value);

	value = (GValue *) g_hash_table_lookup (settings, "baud");
	if (value && G_VALUE_HOLDS_INT (value))
		self->baud = g_value_get_int (value);

	value = (GValue *) g_hash_table_lookup (settings, "mru");
	if (value && G_VALUE_HOLDS_INT (value))
		self->mru = g_value_get_int (value);

	value = (GValue *) g_hash_table_lookup (settings, "mtu");
	if (value && G_VALUE_HOLDS_INT (value))
		self->mtu = g_value_get_int (value);

	value = (GValue *) g_hash_table_lookup (settings, "lcp-echo-failure");
	if (value && G_VALUE_HOLDS_INT (value))
		self->lcp_echo_failure = g_value_get_int (value);

	value = (GValue *) g_hash_table_lookup (settings, "lcp-echo-interval");
	if (value && G_VALUE_HOLDS_INT (value))
		self->lcp_echo_interval = g_value_get_int (value);

	return setting;
}
