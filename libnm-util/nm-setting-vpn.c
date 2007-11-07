/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>
#include <dbus/dbus-glib.h>
#include "nm-setting-vpn.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMSettingVPN, nm_setting_vpn, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_SERVICE_TYPE,
	PROP_USER_NAME,
	PROP_ROUTES,

	LAST_PROP
};

NMSetting *
nm_setting_vpn_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VPN, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings)
{
	NMSettingVPN *self = NM_SETTING_VPN (setting);

	if (!self->service_type || !strlen (self->service_type))
		return FALSE;

	/* default username can be NULL, but can't be zero-length */
	if (self->user_name && !strlen (self->user_name))
		return FALSE;

	return TRUE;
}

static void
nm_setting_vpn_init (NMSettingVPN *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_VPN_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingVPN *self = NM_SETTING_VPN (object);

	g_free (self->service_type);
	g_free (self->user_name);
	nm_utils_slist_free (self->routes, g_free);

	G_OBJECT_CLASS (nm_setting_vpn_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingVPN *setting = NM_SETTING_VPN (object);

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_free (setting->service_type);
		setting->service_type = g_value_dup_string (value);
		break;
	case PROP_USER_NAME:
		g_free (setting->user_name);
		setting->user_name = g_value_dup_string (value);
		break;
	case PROP_ROUTES:
		nm_utils_slist_free (setting->routes, g_free);
		setting->routes = g_value_dup_boxed (value);
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
	NMSettingVPN *setting = NM_SETTING_VPN (object);

	switch (prop_id) {
	case PROP_SERVICE_TYPE:
		g_value_set_string (value, setting->service_type);
		break;
	case PROP_USER_NAME:
		g_value_set_string (value, setting->user_name);
		break;
	case PROP_ROUTES:
		g_value_set_boxed (value, setting->routes);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_vpn_class_init (NMSettingVPNClass *setting_class)
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
		(object_class, PROP_SERVICE_TYPE,
		 g_param_spec_string (NM_SETTING_VPN_SERVICE_TYPE,
						  "Service type",
						  "Service type",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_USER_NAME,
		 g_param_spec_string (NM_SETTING_VPN_USER_NAME,
						  "User name",
						  "User name",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 nm_param_spec_specialized (NM_SETTING_VPN_ROUTES,
							   "Routes",
							   "Routes",
							   dbus_g_type_get_collection ("GSList", G_TYPE_STRING),
							   G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
