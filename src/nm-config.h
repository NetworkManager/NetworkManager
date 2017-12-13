/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#ifndef __NETWORKMANAGER_CONFIG_H__
#define __NETWORKMANAGER_CONFIG_H__

#include "nm-config-data.h"

#define NM_TYPE_CONFIG            (nm_config_get_type ())
#define NM_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG, NMConfig))
#define NM_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CONFIG, NMConfigClass))
#define NM_IS_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG))
#define NM_IS_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CONFIG))
#define NM_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CONFIG, NMConfigClass))

/* Properties */
#define NM_CONFIG_CMD_LINE_OPTIONS                  "cmd-line-options"
#define NM_CONFIG_ATOMIC_SECTION_PREFIXES           "atomic-section-prefixes"

/* Signals */
#define NM_CONFIG_SIGNAL_CONFIG_CHANGED             "config-changed"

#define NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL 300
#define NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE "NetworkManager is online" /* NOT LOCALIZED */

#define NM_CONFIG_KEYFILE_LIST_SEPARATOR ','

#define NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN                ".intern."
#define NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION            "connection"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE                "device"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN     "global-dns-domain-"
#define NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST ".test-append-stringlist"

#define NM_CONFIG_KEYFILE_GROUP_MAIN                        "main"
#define NM_CONFIG_KEYFILE_GROUP_LOGGING                     "logging"
#define NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY                "connectivity"
#define NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS                  "global-dns"
#define NM_CONFIG_KEYFILE_GROUP_CONFIG                      ".config"

#define NM_CONFIG_KEYFILE_GROUP_KEYFILE                     "keyfile"
#define NM_CONFIG_KEYFILE_GROUP_IFUPDOWN                    "ifupdown"

#define NM_CONFIG_KEYFILE_KEY_MAIN_AUTH_POLKIT              "auth-polkit"
#define NM_CONFIG_KEYFILE_KEY_MAIN_AUTOCONNECT_RETRIES_DEFAULT "autoconnect-retries-default"
#define NM_CONFIG_KEYFILE_KEY_MAIN_DHCP                     "dhcp"
#define NM_CONFIG_KEYFILE_KEY_MAIN_DEBUG                    "debug"
#define NM_CONFIG_KEYFILE_KEY_MAIN_HOSTNAME_MODE            "hostname-mode"
#define NM_CONFIG_KEYFILE_KEY_MAIN_SLAVES_ORDER             "slaves-order"
#define NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND               "backend"
#define NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE                 "enable"
#define NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS            ".was"
#define NM_CONFIG_KEYFILE_KEY_KEYFILE_PATH                  "path"
#define NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES     "unmanaged-devices"
#define NM_CONFIG_KEYFILE_KEY_KEYFILE_HOSTNAME              "hostname"
#define NM_CONFIG_KEYFILE_KEY_IFNET_AUTO_REFRESH            "auto_refresh"
#define NM_CONFIG_KEYFILE_KEY_IFNET_MANAGED                 "managed"
#define NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED              "managed"
#define NM_CONFIG_KEYFILE_KEY_AUDIT                         "audit"

#define NM_CONFIG_KEYFILE_KEY_DEVICE_MANAGED                "managed"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_IGNORE_CARRIER         "ignore-carrier"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_SRIOV_NUM_VFS          "sriov-num-vfs"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_BACKEND           "wifi.backend"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_SCAN_RAND_MAC_ADDRESS "wifi.scan-rand-mac-address"
#define NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT   "carrier-wait-timeout"

#define NM_CONFIG_KEYFILE_KEYPREFIX_WAS                     ".was."
#define NM_CONFIG_KEYFILE_KEYPREFIX_SET                     ".set."

#define NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS \
	NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS
#define NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN \
	NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN

typedef struct NMConfigCmdLineOptions NMConfigCmdLineOptions;

typedef enum {
	NM_CONFIG_STATE_PROPERTY_NONE,

	/* 1 set-argument: (gboolean enabled) */
	NM_CONFIG_STATE_PROPERTY_NETWORKING_ENABLED,
	NM_CONFIG_STATE_PROPERTY_WIFI_ENABLED,
	NM_CONFIG_STATE_PROPERTY_WWAN_ENABLED,
} NMConfigRunStatePropertyType;

typedef struct {
	bool net_enabled;
	bool wifi_enabled;
	bool wwan_enabled;

	/* Whether the runstate is modified and not saved to disk. */
	bool dirty;
} NMConfigState;

typedef struct _NMConfigClass NMConfigClass;

GType nm_config_get_type (void);

NMConfig *nm_config_get (void);

const char *nm_config_change_flags_to_string (NMConfigChangeFlags flags, char *buf, gsize len);

NMConfigData *nm_config_get_data (NMConfig *config);
NMConfigData *nm_config_get_data_orig (NMConfig *config);

#define NM_CONFIG_GET_DATA      (nm_config_get_data (nm_config_get ()))
#define NM_CONFIG_GET_DATA_ORIG (nm_config_get_data_orig (nm_config_get ()))

gboolean nm_config_get_monitor_connection_files (NMConfig *config);
const char *nm_config_get_log_level (NMConfig *config);
const char *nm_config_get_log_domains (NMConfig *config);
gboolean nm_config_get_configure_and_quit (NMConfig *config);
gboolean nm_config_get_is_debug (NMConfig *config);

gboolean nm_config_get_first_start (NMConfig *config);

void nm_config_set_values (NMConfig *self,
                           GKeyFile *keyfile_intern_new,
                           gboolean allow_write,
                           gboolean force_rewrite);

/* for main.c only */
NMConfigCmdLineOptions *nm_config_cmd_line_options_new (gboolean first_start);
void                    nm_config_cmd_line_options_free (NMConfigCmdLineOptions *cli);
void                    nm_config_cmd_line_options_add_to_entries (NMConfigCmdLineOptions *cli,
                                                                   GOptionContext *opt_ctx);

gboolean nm_config_get_no_auto_default_for_device (NMConfig *config, NMDevice *device);
void nm_config_set_no_auto_default_for_device  (NMConfig *config, NMDevice *device);

NMConfig *nm_config_new (const NMConfigCmdLineOptions *cli, char **atomic_section_prefixes, GError **error);
NMConfig *nm_config_setup (const NMConfigCmdLineOptions *cli, char **atomic_section_prefixes, GError **error);
void nm_config_reload (NMConfig *config, NMConfigChangeFlags reload_flags);

const NMConfigState *nm_config_state_get (NMConfig *config);

void _nm_config_state_set (NMConfig *config,
                           gboolean allow_persist,
                           gboolean force_persist,
                           ...);
#define nm_config_state_set(config, allow_persist, force_persist, ...) \
    _nm_config_state_set (config, allow_persist, force_persist, ##__VA_ARGS__, 0)

gint nm_config_parse_boolean (const char *str, gint default_value);

GKeyFile *nm_config_create_keyfile (void);
gint nm_config_keyfile_get_boolean (const GKeyFile *keyfile,
                                    const char *section,
                                    const char *key,
                                    gint default_value);
gint64 nm_config_keyfile_get_int64 (const GKeyFile *keyfile,
                                    const char *section,
                                    const char *key,
                                    guint base,
                                    gint64 min,
                                    gint64 max,
                                    gint64 fallback);
char *nm_config_keyfile_get_value (const GKeyFile *keyfile,
                                   const char *section,
                                   const char *key,
                                   NMConfigGetValueFlags flags);
void nm_config_keyfile_set_string_list (GKeyFile *keyfile,
                                        const char *group,
                                        const char *key,
                                        const char *const* strv,
                                        gssize len);
gboolean nm_config_keyfile_has_global_dns_config (GKeyFile *keyfile, gboolean internal);

GSList *nm_config_get_match_spec (const GKeyFile *keyfile, const char *group, const char *key, gboolean *out_has_key);

void _nm_config_sort_groups (char **groups, gsize ngroups);

gboolean nm_config_set_global_dns (NMConfig *self, NMGlobalDnsConfig *global_dns, GError **error);

void nm_config_set_connectivity_check_enabled (NMConfig *self, gboolean enabled);

/* internal defines ... */
extern guint _nm_config_match_nm_version;
extern char *_nm_config_match_env;

/*****************************************************************************/

#define NM_CONFIG_DEVICE_STATE_DIR ""NMRUNDIR"/devices"

#define NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_BOOL     (nm_streq (""NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT, "true"))
#define NM_CONFIG_DEFAULT_LOGGING_AUDIT_BOOL        (nm_streq (""NM_CONFIG_DEFAULT_LOGGING_AUDIT, "true"))

typedef enum {
	NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNKNOWN   = -1,
	NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNMANAGED = 0,
	NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED   = 1,
} NMConfigDeviceStateManagedType;

struct _NMConfigDeviceStateData {
	int ifindex;
	NMConfigDeviceStateManagedType managed;

	/* a value of zero means that no metric is set. */
	guint32 route_metric_default_aspired;
	guint32 route_metric_default_effective;

	/* the UUID of the last settings-connection active
	 * on the device. */
	const char *connection_uuid;

	const char *perm_hw_addr_fake;

	/* whether the device was nm-owned (0/1) or -1 for
	 * non-software devices. */
	int nm_owned:3;
};

NMConfigDeviceStateData *nm_config_device_state_load (int ifindex);
GHashTable *nm_config_device_state_load_all (void);
gboolean nm_config_device_state_write (int ifindex,
                                       NMConfigDeviceStateManagedType managed,
                                       const char *perm_hw_addr_fake,
                                       const char *connection_uuid,
                                       gint nm_owned,
                                       guint32 route_metric_default_aspired,
                                       guint32 route_metric_default_effective);

void nm_config_device_state_prune_unseen (GHashTable *seen_ifindexes);

const GHashTable *nm_config_device_state_get_all (NMConfig *self);
const NMConfigDeviceStateData *nm_config_device_state_get (NMConfig *self,
                                                           int ifindex);

/*****************************************************************************/

#endif /* __NETWORKMANAGER_CONFIG_H__ */
