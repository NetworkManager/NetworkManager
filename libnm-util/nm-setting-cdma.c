/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include "nm-setting-cdma.h"
#include "nm-setting-serial.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMSettingCdma, nm_setting_cdma, NM_TYPE_SETTING)

enum {
	PROP_0,
	PROP_NUMBER,
	PROP_USERNAME,
	PROP_PASSWORD,

	LAST_PROP
};

NMSetting *
nm_setting_cdma_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_CDMA, NULL);
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings)
{
	NMSettingCdma *self = NM_SETTING_CDMA (setting);

	/* Serial connections require a PPP setting */
	if (all_settings && 
	    !g_slist_find_custom (all_settings, NM_SETTING_SERIAL_SETTING_NAME, find_setting_by_name)) {
		g_warning ("Missing serial setting");
		return FALSE;
	}

	if (!self->number || strlen (self->number) < 1) {
		nm_warning ("Missing phone number");
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_cdma_init (NMSettingCdma *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_CDMA_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingCdma *self = NM_SETTING_CDMA (object);

	g_free (self->number);
	g_free (self->username);
	g_free (self->password);

	G_OBJECT_CLASS (nm_setting_cdma_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingCdma *setting = NM_SETTING_CDMA (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_free (setting->number);
		setting->number = g_value_dup_string (value);
		break;
	case PROP_USERNAME:
		g_free (setting->username);
		setting->username = g_value_dup_string (value);
		break;
	case PROP_PASSWORD:
		g_free (setting->password);
		setting->password = g_value_dup_string (value);
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
	NMSettingCdma *setting = NM_SETTING_CDMA (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_value_set_string (value, setting->number);
		break;
	case PROP_USERNAME:
		g_value_set_string (value, setting->username);
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, setting->password);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_cdma_class_init (NMSettingCdmaClass *setting_class)
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
		(object_class, PROP_NUMBER,
		 g_param_spec_string (NM_SETTING_CDMA_NUMBER,
						  "Number",
						  "Number",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_CDMA_USERNAME,
						  "Username",
						  "Username",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_CDMA_PASSWORD,
						  "Password",
						  "Password",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));
}
