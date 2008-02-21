/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib/gtypes.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING            (nm_setting_get_type ())
#define NM_SETTING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING, NMSetting))
#define NM_SETTING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING, NMSettingClass))
#define NM_IS_SETTING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING))
#define NM_IS_SETTING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING))
#define NM_SETTING_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING, NMSettingClass))

#define NM_SETTING_PARAM_SERIALIZE    (1 << (0 + G_PARAM_USER_SHIFT))
#define NM_SETTING_PARAM_REQUIRED     (1 << (1 + G_PARAM_USER_SHIFT))
#define NM_SETTING_PARAM_SECRET       (1 << (2 + G_PARAM_USER_SHIFT))
#define NM_SETTING_PARAM_FUZZY_IGNORE (1 << (3 + G_PARAM_USER_SHIFT))

#define NM_SETTING_NAME "name"

typedef struct {
	GObject parent;

	char *name;
} NMSetting;

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	gboolean    (*verify)            (NMSetting  *setting,
	                                  GSList     *all_settings);

	GPtrArray  *(*need_secrets)      (NMSetting  *setting);

	void        (*update_one_secret) (NMSetting  *setting,
	                                  const char *key,
	                                  GValue     *value);
} NMSettingClass;

typedef void (*NMSettingValueIterFn) (NMSetting *setting,
							   const char *key,
							   const GValue *value,
							   gboolean secret,
							   gpointer user_data);


GType nm_setting_get_type (void);

GHashTable *nm_setting_to_hash       (NMSetting *setting);
NMSetting  *nm_setting_from_hash     (GType setting_type,
							   GHashTable *hash);

const char *nm_setting_get_name      (NMSetting *setting);

gboolean    nm_setting_verify        (NMSetting *setting,
							   GSList    *all_settings);


typedef enum {
	/* Match all attributes exactly */
	COMPARE_FLAGS_EXACT = 0x00,

	/* Match only important attributes, like SSID, type, security settings, etc */
	COMPARE_FLAGS_FUZZY = 0x01,
} NMSettingCompareFlags;

gboolean    nm_setting_compare       (NMSetting *setting,
                                      NMSetting *other,
                                      NMSettingCompareFlags flags);

void        nm_setting_enumerate_values (NMSetting *setting,
                                         NMSettingValueIterFn func,
                                         gpointer user_data);

char       *nm_setting_to_string      (NMSetting *setting);

/* Secrets */
void        nm_setting_clear_secrets  (NMSetting *setting);
GPtrArray  *nm_setting_need_secrets   (NMSetting *setting);
void        nm_setting_update_secrets (NMSetting *setting,
							    GHashTable *secrets);

G_END_DECLS

#endif /* NM_SETTING_H */

