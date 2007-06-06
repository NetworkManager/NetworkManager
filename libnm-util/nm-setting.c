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

	/* First, make sure there's at least 'info' setting */
	p = g_hash_table_lookup (all_settings, "info");
	if (!p) {
		g_warning ("'info' setting not present.");
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
byte_array_to_gvalue (GByteArray *array)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_set_boxed (val, array);

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

/***********************************************************************/

/* Info */

static gboolean
setting_info_verify (NMSetting *setting, GHashTable *all_settings)
{
	NMSettingInfo *self = (NMSettingInfo *) setting;

	/* Make sure the corresponding 'devtype' item is present */
	if (!g_hash_table_lookup (all_settings, self->devtype))
		return FALSE;

	return TRUE;
}

static GHashTable *
setting_info_hash (NMSetting *setting)
{
	NMSettingInfo *self = (NMSettingInfo *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "name", string_to_gvalue (self->name));
	g_hash_table_insert (hash, "devtype", string_to_gvalue (self->devtype));
	g_hash_table_insert (hash, "autoconnect", boolean_to_gvalue (self->autoconnect));

	return hash;
}

static void
setting_info_destroy (NMSetting *setting)
{
	NMSettingInfo *self = (NMSettingInfo *) setting;

	g_free (self->name);
	g_free (self->devtype);

	g_slice_free (NMSettingInfo, self);
}

NMSetting *
nm_setting_info_new (void)
{
	NMSetting *setting;

	setting = (NMSetting *) g_slice_new0 (NMSettingInfo);

	setting->name = g_strdup ("info");
	setting->verify_fn = setting_info_verify;
	setting->hash_fn = setting_info_hash;
	setting->destroy_fn = setting_info_destroy;

	return setting;
}

NMSetting *
nm_setting_info_new_from_hash (GHashTable *settings)
{
	NMSettingInfo *self;
	NMSetting *setting;
	GValue *value;

	g_return_val_if_fail (settings != NULL, NULL);

	setting = nm_setting_info_new ();
	self = (NMSettingInfo *) setting;

	value = (GValue *) g_hash_table_lookup (settings, "name");
	if (value && G_VALUE_HOLDS_STRING (value))
		self->name = g_strdup (g_value_get_string (value));
	else {
		g_warning ("Missing or invalid info name");
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
	setting_info_destroy (setting);

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

	if (self->port) {
		char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
		int i;

		for (i = 0; valid_ports[i]; i++) {
			if (strcmp (self->port, valid_ports[i]) == 0)
				break;
		}

		if (valid_ports[i] == NULL) {
			g_warning ("Invalid port");
			return FALSE;
		}
	}

	if (self->duplex && strcmp (self->duplex, "half") && strcmp (self->duplex, "full")) {
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
	GSList *iter;

	if (!self->ssid || self->ssid->len < 1 || self->ssid->len > 32) {
		g_warning ("Invalid or missing ssid");
		return FALSE;
	}

	if (self->mode && strcmp (self->mode, "infrastructure") && strcmp (self->mode, "adhoc")) {
		g_warning ("Invalid mode. Should be either 'infrastructure' or 'adhoc'");
		return FALSE;
	}

	if (self->band && strcmp (self->band, "a") && strcmp (self->band, "bg")) {
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

	return TRUE;
}

static GHashTable *
setting_wireless_hash (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;
	GHashTable *hash;

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
		g_hash_table_insert (hash, "security", string_to_gvalue (self->mode));

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
