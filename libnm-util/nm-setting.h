/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_H
#define NM_SETTING_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct _NMSetting NMSetting;

typedef NMSetting *(*NMSettingCreateFn)  (void);
typedef gboolean  (*NMSettingPopulateFn) (NMSetting *setting,
								  GHashTable *hash);
typedef gboolean   (*NMSettingVerifyFn)  (NMSetting *setting,
								  GHashTable *all_settings);

typedef GHashTable *(*NMSettingToHashFn) (NMSetting *setting);

typedef gboolean   (*NMSettingUpdateSecretsFn) (NMSetting *setting,
                                                GHashTable *secrets);

typedef GPtrArray *(*NMSettingNeedSecretsFn) (NMSetting *setting);

typedef void       (*NMSettingClearSecretsFn) (NMSetting *setting);

typedef gboolean   (*NMSettingCompareFn) (NMSetting *setting,
                                          NMSetting *other,
                                          gboolean two_way);

typedef void       (*NMSettingDestroyFn) (NMSetting *setting);

typedef void   (*NMSettingValueIterFn) (NMSetting *setting,
                                        const char *key,
                                        guint32 type,
                                        void *value,
                                        gboolean secret,
                                        gpointer user_data);

#define NM_S_TYPE_STRING         1
#define NM_S_TYPE_UINT32         2
#define NM_S_TYPE_BOOL           3
#define NM_S_TYPE_BYTE_ARRAY     4
#define NM_S_TYPE_STRING_ARRAY   5
#define NM_S_TYPE_GVALUE_HASH    6
#define NM_S_TYPE_UINT64         7
#define NM_S_TYPE_UINT_ARRAY     8

#define NM_S_TYPE_IP4_ADDRESSES  9


typedef struct SettingMember {
	const char *key;
	guint32 type;
	gulong offset;
	gboolean required;
	gboolean secret;
} SettingMember;

struct _NMSetting {
	char *name;
	SettingMember *_members;  /* Private */

	NMSettingPopulateFn populate_fn;
	NMSettingVerifyFn verify_fn;
	NMSettingToHashFn hash_fn;
	NMSettingUpdateSecretsFn update_secrets_fn;
	NMSettingNeedSecretsFn need_secrets_fn;
	NMSettingClearSecretsFn clear_secrets_fn;
	NMSettingCompareFn compare_fn;
	NMSettingDestroyFn destroy_fn;
};

gboolean    nm_settings_verify_all (GHashTable *all_settings);

gboolean    nm_setting_populate_from_hash (NMSetting *setting, GHashTable *hash);
gboolean    nm_setting_verify (NMSetting *setting);
gboolean    nm_setting_compare (NMSetting *setting, NMSetting *other, gboolean two_way);
GHashTable *nm_setting_to_hash (NMSetting *setting);
gboolean    nm_setting_update_secrets (NMSetting *setting, GHashTable *secrets);
GPtrArray * nm_setting_need_secrets (NMSetting *setting);
void        nm_setting_clear_secrets (NMSetting *setting);
void        nm_setting_destroy (NMSetting *setting);
void        nm_setting_enumerate_values (NMSetting *setting,
                                         NMSettingValueIterFn func,
                                         gpointer user_data);

/* Default, built-in settings */

/* Connection */

#define NM_SETTING_CONNECTION "connection"

typedef struct {
	NMSetting parent;

	char *name;
	char *type;
	gboolean autoconnect;
	guint64 timestamp;
} NMSettingConnection;

NMSetting *nm_setting_connection_new (void);

/* IP4 config */

#define NM_SETTING_IP4_CONFIG "ipv4"

typedef struct {
	guint32 address;
	guint32 netmask;
	guint32 gateway;
} NMSettingIP4Address;

typedef struct {
	NMSetting parent;

	gboolean manual;
	GArray *dns;
	GSList *dns_search; /* GSList of strings */
	GSList *addresses; /* GSList of NMSettingIP4Address */
} NMSettingIP4Config;

NMSetting *nm_setting_ip4_config_new (void);

/* Wired device */

#define NM_SETTING_WIRED "802-3-ethernet"

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

/* Wireless device */

#define NM_SETTING_WIRELESS "802-11-wireless"

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

/* Wireless security */

#define NM_SETTING_WIRELESS_SECURITY "802-11-wireless-security"

typedef struct {
	NMSetting parent;

	char *key_mgmt;
	guint32 wep_tx_keyidx;
	char *auth_alg;
	GSList *proto; /* GSList of strings */
	GSList *pairwise; /* GSList of strings */
	GSList *group; /* GSList of strings */
	GSList *eap; /* GSList of strings */
	char *identity;
	char *anonymous_identity;
	GByteArray *ca_cert;
	char *ca_path;
	GByteArray *client_cert;
	GByteArray *private_key;
	char *phase1_peapver;
	char *phase1_peaplabel;
	char *phase1_fast_provisioning;
	char *phase2_auth;
	char *phase2_autheap;
	GByteArray *phase2_ca_cert;
	char *phase2_ca_path;
	GByteArray *phase2_client_cert;
	GByteArray *phase2_private_key;
	char *nai;
	char *wep_key0;
	char *wep_key1;
	char *wep_key2;
	char *wep_key3;
	char *psk;
	char *password;
	char *pin;
	char *eappsk;
	char *private_key_passwd;
	char *phase2_private_key_passwd;
} NMSettingWirelessSecurity;

NMSetting *nm_setting_wireless_security_new (void);

/* PPP */

#define NM_SETTING_PPP "ppp"

typedef struct {
	NMSetting parent;

	gboolean noauth;
	gboolean refuse_eap;
	gboolean refuse_chap;
	gboolean refuse_mschap;
	gboolean nobsdcomp;
	gboolean nodeflate;
	gboolean require_mppe;
	gboolean require_mppe_128;
	gboolean mppe_stateful;
	gboolean require_mppc;
	gboolean crtscts;
	gboolean usepeerdns;

	gint32 baud;
	gint32 mru;
	gint32 mtu;
	gint32 lcp_echo_failure;
	gint32 lcp_echo_interval;
} NMSettingPPP;

NMSetting *nm_setting_ppp_new (void);

/* VPN */

#define NM_SETTING_VPN "vpn"

typedef struct {
	NMSetting parent;

	char *service_type;
	char *user_name;
	GSList *routes;
} NMSettingVPN;

NMSetting *nm_setting_vpn_new (void);

/* VPN properties */

#define NM_SETTING_VPN_PROPERTIES "vpn-properties"

typedef struct {
	NMSetting parent;

	GHashTable *data;
} NMSettingVPNProperties;

NMSetting *nm_setting_vpn_properties_new (void);

G_END_DECLS

#endif /* NM_SETTING_H */
