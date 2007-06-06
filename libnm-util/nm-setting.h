#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib.h>

typedef struct _NMSetting NMSetting;

typedef NMSetting *(*NMSettingCreateFn)  (GHashTable *settings);
typedef gboolean   (*NMSettingVerifyFn)  (NMSetting *setting,
										  GHashTable *all_settings);

typedef GHashTable *(*NMSettingToHashFn) (NMSetting *setting);

typedef void       (*NMSettingDestroyFn) (NMSetting *setting);

struct _NMSetting {
	char *name;

	NMSettingVerifyFn verify_fn;
	NMSettingToHashFn hash_fn;
	NMSettingDestroyFn destroy_fn;
};

gboolean    nm_settings_verify (GHashTable *all_settings);
GHashTable *nm_setting_to_hash (NMSetting *setting);
void        nm_setting_destroy (NMSetting *setting);

/* Default, built-in settings */

/* Info */

typedef struct {
	NMSetting parent;

	char *name;
	char *devtype;
	gboolean autoconnect;
} NMSettingInfo;

NMSetting *nm_setting_info_new (void);
NMSetting *nm_setting_info_new_from_hash (GHashTable *settings);

/* IP4 config */

typedef struct {
	NMSetting parent;

	gboolean manual;
	guint32 address;
	guint32 netmask;
	guint32 gateway;
} NMSettingIP4Config;

NMSetting *nm_setting_ip4_config_new (void);
NMSetting *nm_setting_ip4_config_new_from_hash (GHashTable *settings);

/* Wired device */

typedef struct {
	NMSetting parent;

	char *port;
	guint32 speed;
	char *duplex;
	gboolean auto_negotiate;
	GByteArray *mac_address;
	guint32 mtu;
} NMSettingWired;

NMSetting *nm_setting_wired_new (void);
NMSetting *nm_setting_wired_new_from_hash (GHashTable *settings);

/* Wireless device */

typedef struct {
	NMSetting parent;

	GByteArray *ssid;
	char *mode;
	char *band;
	guint32 channel;
	GByteArray *bssid;
	guint32 rate;
	guint32 tx_power;
	GByteArray *mac_address;
	guint32 mtu;
	GSList *seen_bssids;
	char *security;
} NMSettingWireless;

NMSetting *nm_setting_wireless_new (void);
NMSetting *nm_setting_wireless_new_from_hash (GHashTable *settings);

#endif /* NM_SETTING_H */
