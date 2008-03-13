/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include <dbus/dbus-glib.h>
#include "nm-setting-ip4-config.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMSettingIP4Config, nm_setting_ip4_config, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_ADDRESSES,

	LAST_PROP
};

NMSetting *
nm_setting_ip4_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_IP4_CONFIG, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (setting);

	if (!self->method)
		return FALSE;

	if (!strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_MANUAL)) {
		if (!self->addresses) {
			g_warning ("address is not provided");
			return FALSE;
		}
	} else if (!strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_AUTOIP)) {
		if (self->dns && self->dns->len) {
			g_warning ("may not specify DNS when using autoip");
			return FALSE;
		}

		if (g_slist_length (self->dns_search)) {
			g_warning ("may not specify DNS searches when using autoip");
			return FALSE;
		}

		if (g_slist_length (self->addresses)) {
			g_warning ("may not specify IP addresses when using autoip");
			return FALSE;
		}
	} else if (!strcmp (self->method, NM_SETTING_IP4_CONFIG_METHOD_DHCP)) {
		/* nothing to do */
	} else {
		g_warning ("invalid IP4 config method '%s'", self->method);
		return FALSE;
	}

	return TRUE;
}


static void
nm_setting_ip4_config_init (NMSettingIP4Config *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_IP4_CONFIG_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingIP4Config *self = NM_SETTING_IP4_CONFIG (object);

	g_free (self->method);

	if (self->dns)
		g_array_free (self->dns, TRUE);

	nm_utils_slist_free (self->dns_search, g_free);
	nm_utils_slist_free (self->addresses, g_free);

	G_OBJECT_CLASS (nm_setting_ip4_config_parent_class)->finalize (object);
}

static GSList *
ip4_addresses_from_gvalue (const GValue *value)
{
	GPtrArray *addresses;
	int i;
	GSList *list = NULL;

	addresses = (GPtrArray *) g_value_get_boxed (value);
	for (i = 0; i < addresses->len; i++) {
		GArray *array = (GArray *) g_ptr_array_index (addresses, i);

		if (array->len == 2 || array->len == 3) {
			NMSettingIP4Address *ip4_addr;

			ip4_addr = g_new0 (NMSettingIP4Address, 1);
			ip4_addr->address = g_array_index (array, guint32, 0);
			ip4_addr->netmask = g_array_index (array, guint32, 1);

			if (array->len == 3)
				ip4_addr->gateway = g_array_index (array, guint32, 2);

			list = g_slist_prepend (list, ip4_addr);
		} else
			nm_warning ("Ignoring invalid IP4 address");
	}

	return g_slist_reverse (list);
}

static void
ip4_addresses_to_gvalue (GSList *list, GValue *value)
{
	GPtrArray *addresses;
	GSList *iter;

	addresses = g_ptr_array_new ();

	for (iter = list; iter; iter = iter->next) {
		NMSettingIP4Address *ip4_addr = (NMSettingIP4Address *) iter->data;
		GArray *array;
		const guint32 empty_val = 0;

		array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), 3);

		g_array_append_val (array, ip4_addr->address);
		g_array_append_val (array, ip4_addr->netmask);

		if (ip4_addr->gateway)
			g_array_append_val (array, ip4_addr->gateway);
		else
			g_array_append_val (array, empty_val);

		g_ptr_array_add (addresses, array);
	}

	g_value_take_boxed (value, addresses);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_free (setting->method);
		setting->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		if (setting->dns)
			g_array_free (setting->dns, TRUE);
		setting->dns = g_value_dup_boxed (value);
		break;
	case PROP_DNS_SEARCH:
		nm_utils_slist_free (setting->dns_search, g_free);
		setting->dns_search = g_value_dup_boxed (value);
		break;
	case PROP_ADDRESSES:
		nm_utils_slist_free (setting->addresses, g_free);
		setting->addresses = ip4_addresses_from_gvalue (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingIP4Config *setting = NM_SETTING_IP4_CONFIG (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, setting->method);
		break;
	case PROP_DNS:
		g_value_set_boxed (value, setting->dns);
		break;
	case PROP_DNS_SEARCH:
		g_value_set_boxed (value, setting->dns_search);
		break;
	case PROP_ADDRESSES:
		ip4_addresses_to_gvalue (setting->addresses, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_ip4_config_class_init (NMSettingIP4ConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP4_CONFIG_METHOD,
						      "Method",
						      "IP configuration method",
						      NULL,
						      G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS,
							   "DNS",
							   "List of DNS servers",
							   DBUS_TYPE_G_UINT_ARRAY,
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_DNS_SEARCH,
							   "DNS search",
							   "List of DNS search domains",
							   dbus_g_type_get_collection ("GSList", G_TYPE_STRING),
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 nm_param_spec_specialized (NM_SETTING_IP4_CONFIG_ADDRESSES,
							   "Addresses",
							   "List of NMSettingIP4Addresses",
							   dbus_g_type_get_collection ("GPtrArray", dbus_g_type_get_collection ("GArray", G_TYPE_UINT)),
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
