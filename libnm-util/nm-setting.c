#include <glib-object.h>

#include "nm-setting.h"

static void
dump_one_setting (gpointer key, gpointer value, gpointer user_data)
{
	NMSetting *setting = (NMSetting *) value;

	g_message ("Setting '%s'", setting->name);
	if (setting->dump_fn)
		setting->dump_fn (setting);
	g_message ("-------------------");
}

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

	/* Debug dump */
	g_hash_table_foreach (all_settings, dump_one_setting, NULL);

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

/***********************************************************************/

static void
setting_info_dump (NMSetting *setting)
{
	NMSettingInfo *self = (NMSettingInfo *) setting;

	g_message ("info name: %s", self->name);
	g_message ("devtype: %s", self->devtype);
	g_message ("autoconnect: %s", self->autoconnect ? "Yes" : "No");
}

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
	setting->dump_fn = setting_info_dump;
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


static void
setting_wired_dump (NMSetting *setting)
{
	NMSettingWired *self = (NMSettingWired *) setting;

	g_message ("MTU: %d", self->mtu);
}

static gboolean
setting_wired_verify (NMSetting *setting, GHashTable *all_settings)
{
	return TRUE;
}

static GHashTable *
setting_wired_hash (NMSetting *setting)
{
	NMSettingWired *self = (NMSettingWired *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "mtu", int_to_gvalue (self->mtu));

	return hash;
}

static void
setting_wired_destroy (NMSetting *setting)
{
	NMSettingWired *self = (NMSettingWired *) setting;

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
	setting->dump_fn = setting_wired_dump;
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

	value = (GValue *) g_hash_table_lookup (settings, "mtu");
	if (value && G_VALUE_HOLDS_INT (value))
		self->mtu = g_value_get_int (value);

	return setting;
}


static void
setting_wireless_dump (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;

	g_message ("ssid: %s", self->ssid);
	g_message ("mode: %d", self->mode);
}

static gboolean
setting_wireless_verify (NMSetting *setting, GHashTable *all_settings)
{
	return TRUE;
}

static GHashTable *
setting_wireless_hash (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;
	GHashTable *hash;

	hash = setting_hash_new ();
	g_hash_table_insert (hash, "ssid", string_to_gvalue (self->ssid));
	g_hash_table_insert (hash, "mode", int_to_gvalue (self->mode));

	return hash;
}


static void
setting_wireless_destroy (NMSetting *setting)
{
	NMSettingWireless *self = (NMSettingWireless *) setting;

	g_free (self->ssid);

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
	setting->dump_fn = setting_wireless_dump;
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
	if (value && G_VALUE_HOLDS_STRING (value))
		self->ssid = g_strdup (g_value_get_string (value));
	else {
		g_warning ("Missing or invalid ssid");
		goto err;
	}

	value = (GValue *) g_hash_table_lookup (settings, "mode");
	if (value && G_VALUE_HOLDS_INT (value)) {
		self->mode = g_value_get_int (value);
	} else {
		g_warning ("Missing or invalid mode");
		goto err;
	}

	return setting;

 err:
	setting_wireless_destroy (setting);

	return NULL;
}
