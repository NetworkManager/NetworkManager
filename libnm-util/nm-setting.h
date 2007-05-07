#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib.h>

typedef struct _NMSetting NMSetting;

typedef NMSetting *(*NMSettingCreateFn)  (GHashTable *settings);
typedef gboolean   (*NMSettingVerifyFn)  (NMSetting *setting,
										  GHashTable *all_settings);

typedef GHashTable *(*NMSettingToHashFn) (NMSetting *setting);

typedef void       (*NMSettingDumpFn)    (NMSetting *setting);
typedef void       (*NMSettingDestroyFn) (NMSetting *setting);

struct _NMSetting {
	char *name;

	NMSettingVerifyFn verify_fn;
	NMSettingToHashFn hash_fn;
	NMSettingDumpFn dump_fn;
	NMSettingDestroyFn destroy_fn;
};

gboolean    nm_settings_verify (GHashTable *all_settings);
GHashTable *nm_setting_to_hash (NMSetting *setting);
void        nm_setting_destroy (NMSetting *setting);

/* Default, built-in settings */

typedef struct {
	NMSetting parent;

	char *name;
	char *devtype;
	gboolean autoconnect;
} NMSettingInfo;

NMSetting *nm_setting_info_new (void);
NMSetting *nm_setting_info_new_from_hash (GHashTable *settings);

typedef struct {
	NMSetting parent;

	int mtu;
} NMSettingWired;

NMSetting *nm_setting_wired_new (void);
NMSetting *nm_setting_wired_new_from_hash (GHashTable *settings);

typedef struct {
	NMSetting parent;

	char *ssid;
	int mode;
} NMSettingWireless;

NMSetting *nm_setting_wireless_new (void);
NMSetting *nm_setting_wireless_new_from_hash (GHashTable *settings);

#endif /* NM_SETTING_H */
