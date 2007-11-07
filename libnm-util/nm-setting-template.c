/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* This file is just a template - it's not built nor included in the tarball.
   It's sole purpose is to make the process of creating new settings easier.
   Just replace 'template' with new setting name (preserving the case),
   remove this comment, and you're almost done.
*/

#include "nm-setting-template.h"

G_DEFINE_TYPE (NMSettingTemplate, nm_setting_template, NM_TYPE_SETTING)

enum {
	PROP_0,

	LAST_PROP
};

NMSetting *
nm_setting_template_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TEMPLATE, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings)
{
	NMSettingTemplate *self = NM_SETTING_TEMPLATE (setting);
}

static void
nm_setting_template_init (NMSettingTemplate *setting)
{
	((NMSetting *) setting)->name = g_strdup (NM_SETTING_TEMPLATE_SETTING_NAME);
}

static void
finalize (GObject *object)
{
	NMSettingTemplate *self = NM_SETTING_TEMPLATE (object);

	G_OBJECT_CLASS (nm_setting_template_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingTemplate *setting = NM_SETTING_TEMPLATE (object);

	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMSettingTemplate *setting = NM_SETTING_TEMPLATE (object);

	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_template_class_init (NMSettingTemplateClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
}
