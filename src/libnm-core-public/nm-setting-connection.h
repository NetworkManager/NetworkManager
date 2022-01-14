/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_CONNECTION_H__
#define __NM_SETTING_CONNECTION_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CONNECTION (nm_setting_connection_get_type())
#define NM_SETTING_CONNECTION(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnection))
#define NM_SETTING_CONNECTION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))
#define NM_IS_SETTING_CONNECTION(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_CONNECTION))
#define NM_IS_SETTING_CONNECTION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_CONNECTION))
#define NM_SETTING_CONNECTION_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))

#define NM_SETTING_CONNECTION_SETTING_NAME "connection"

#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN     -999
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX     999
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT 0

#define NM_SETTING_CONNECTION_ID                   "id"
#define NM_SETTING_CONNECTION_UUID                 "uuid"
#define NM_SETTING_CONNECTION_STABLE_ID            "stable-id"
#define NM_SETTING_CONNECTION_INTERFACE_NAME       "interface-name"
#define NM_SETTING_CONNECTION_TYPE                 "type"
#define NM_SETTING_CONNECTION_AUTOCONNECT          "autoconnect"
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY "autoconnect-priority"
#define NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES  "autoconnect-retries"
#define NM_SETTING_CONNECTION_MULTI_CONNECT        "multi-connect"
#define NM_SETTING_CONNECTION_TIMESTAMP            "timestamp"
#define NM_SETTING_CONNECTION_READ_ONLY            "read-only"
#define NM_SETTING_CONNECTION_PERMISSIONS          "permissions"
#define NM_SETTING_CONNECTION_ZONE                 "zone"
#define NM_SETTING_CONNECTION_MASTER               "master"
#define NM_SETTING_CONNECTION_SLAVE_TYPE           "slave-type"
#define NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES   "autoconnect-slaves"
#define NM_SETTING_CONNECTION_SECONDARIES          "secondaries"
#define NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT "gateway-ping-timeout"
#define NM_SETTING_CONNECTION_METERED              "metered"
#define NM_SETTING_CONNECTION_LLDP                 "lldp"
#define NM_SETTING_CONNECTION_AUTH_RETRIES         "auth-retries"
#define NM_SETTING_CONNECTION_MDNS                 "mdns"
#define NM_SETTING_CONNECTION_LLMNR                "llmnr"
#define NM_SETTING_CONNECTION_DNS_OVER_TLS         "dns-over-tls"
#define NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT  "wait-device-timeout"
#define NM_SETTING_CONNECTION_MUD_URL              "mud-url"

/* Types for property values */
/**
 * NMSettingConnectionAutoconnectSlaves:
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT: default value
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO: slaves are not brought up when
 *   master is activated
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES: slaves are brought up when
 *   master is activated
 *
 * #NMSettingConnectionAutoconnectSlaves values indicate whether slave connections
 * should be activated when master is activated.
 */
typedef enum {
    NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT = -1,
    NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO      = 0,
    NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES     = 1,
} NMSettingConnectionAutoconnectSlaves;

/**
 * NMSettingConnectionLldp:
 * @NM_SETTING_CONNECTION_LLDP_DEFAULT: default value
 * @NM_SETTING_CONNECTION_LLDP_DISABLE: disable LLDP
 * @NM_SETTING_CONNECTION_LLDP_ENABLE_RX: enable reception of LLDP frames
 *
 * #NMSettingConnectionLldp values indicate whether LLDP should be enabled.
 */
typedef enum {
    NM_SETTING_CONNECTION_LLDP_DEFAULT   = -1,
    NM_SETTING_CONNECTION_LLDP_DISABLE   = 0,
    NM_SETTING_CONNECTION_LLDP_ENABLE_RX = 1,
} NMSettingConnectionLldp;

/**
 * NMSettingConnectionMdns:
 * @NM_SETTING_CONNECTION_MDNS_DEFAULT: default value
 * @NM_SETTING_CONNECTION_MDNS_NO: disable mDNS
 * @NM_SETTING_CONNECTION_MDNS_RESOLVE: support only resolving, do not register hostname
 * @NM_SETTING_CONNECTION_MDNS_YES: enable mDNS
 *
 * #NMSettingConnectionMdns values indicate whether mDNS should be enabled.
 *
 * Since: 1.12
 */
typedef enum {
    NM_SETTING_CONNECTION_MDNS_DEFAULT = -1,
    NM_SETTING_CONNECTION_MDNS_NO      = 0,
    NM_SETTING_CONNECTION_MDNS_RESOLVE = 1,
    NM_SETTING_CONNECTION_MDNS_YES     = 2,
} NMSettingConnectionMdns;

/**
 * NMSettingConnectionLlmnr:
 * @NM_SETTING_CONNECTION_LLMNR_DEFAULT: default value
 * @NM_SETTING_CONNECTION_LLMNR_NO: disable LLMNR
 * @NM_SETTING_CONNECTION_LLMNR_RESOLVE: support only resolving, do not register hostname
 * @NM_SETTING_CONNECTION_LLMNR_YES: enable LLMNR
 *
 * #NMSettingConnectionLlmnr values indicate whether LLMNR should be enabled.
 *
 * Since: 1.14
 */
typedef enum {
    NM_SETTING_CONNECTION_LLMNR_DEFAULT = -1,
    NM_SETTING_CONNECTION_LLMNR_NO      = 0,
    NM_SETTING_CONNECTION_LLMNR_RESOLVE = 1,
    NM_SETTING_CONNECTION_LLMNR_YES     = 2,
} NMSettingConnectionLlmnr;

/**
 * NMSettingConnectionDnsOverTls:
 * @NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT: default value
 * @NM_SETTING_CONNECTION_DNS_OVER_TLS_NO: disable DNSOverTls
 * @NM_SETTING_CONNECTION_DNS_OVER_TLS_OPPORTUNISTIC: enable opportunistic mode
 * @NM_SETTING_CONNECTION_DNS_OVER_TLS_YES: enable strict mode
 *
 * #NMSettingConnectionDnsOverTls values indicate whether DNSOverTls should be enabled.
 *
 * Since: 1.34
 */
typedef enum {
    NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT       = -1,
    NM_SETTING_CONNECTION_DNS_OVER_TLS_NO            = 0,
    NM_SETTING_CONNECTION_DNS_OVER_TLS_OPPORTUNISTIC = 1,
    NM_SETTING_CONNECTION_DNS_OVER_TLS_YES           = 2,
} NMSettingConnectionDnsOverTls;

typedef struct _NMSettingConnectionClass NMSettingConnectionClass;

GType nm_setting_connection_get_type(void);

NMSetting  *nm_setting_connection_new(void);
const char *nm_setting_connection_get_id(NMSettingConnection *setting);
const char *nm_setting_connection_get_uuid(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_4
const char *nm_setting_connection_get_stable_id(NMSettingConnection *setting);
const char *nm_setting_connection_get_interface_name(NMSettingConnection *setting);
const char *nm_setting_connection_get_connection_type(NMSettingConnection *setting);
gboolean    nm_setting_connection_get_autoconnect(NMSettingConnection *setting);
int         nm_setting_connection_get_autoconnect_priority(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_6
int nm_setting_connection_get_autoconnect_retries(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_14
NMConnectionMultiConnect nm_setting_connection_get_multi_connect(NMSettingConnection *setting);
guint64                  nm_setting_connection_get_timestamp(NMSettingConnection *setting);
gboolean                 nm_setting_connection_get_read_only(NMSettingConnection *setting);

guint32     nm_setting_connection_get_num_permissions(NMSettingConnection *setting);
gboolean    nm_setting_connection_get_permission(NMSettingConnection *setting,
                                                 guint32              idx,
                                                 const char         **out_ptype,
                                                 const char         **out_pitem,
                                                 const char         **out_detail);
const char *nm_setting_connection_get_zone(NMSettingConnection *setting);
gboolean    nm_setting_connection_permissions_user_allowed(NMSettingConnection *setting,
                                                           const char          *uname);
gboolean    nm_setting_connection_add_permission(NMSettingConnection *setting,
                                                 const char          *ptype,
                                                 const char          *pitem,
                                                 const char          *detail);
void        nm_setting_connection_remove_permission(NMSettingConnection *setting, guint32 idx);
gboolean    nm_setting_connection_remove_permission_by_value(NMSettingConnection *setting,
                                                             const char          *ptype,
                                                             const char          *pitem,
                                                             const char          *detail);

const char *nm_setting_connection_get_master(NMSettingConnection *setting);
gboolean    nm_setting_connection_is_slave_type(NMSettingConnection *setting, const char *type);
const char *nm_setting_connection_get_slave_type(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_2
NMSettingConnectionAutoconnectSlaves
nm_setting_connection_get_autoconnect_slaves(NMSettingConnection *setting);

guint32     nm_setting_connection_get_num_secondaries(NMSettingConnection *setting);
const char *nm_setting_connection_get_secondary(NMSettingConnection *setting, guint32 idx);
gboolean    nm_setting_connection_add_secondary(NMSettingConnection *setting, const char *sec_uuid);
void        nm_setting_connection_remove_secondary(NMSettingConnection *setting, guint32 idx);
gboolean    nm_setting_connection_remove_secondary_by_value(NMSettingConnection *setting,
                                                            const char          *sec_uuid);

guint32 nm_setting_connection_get_gateway_ping_timeout(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_2
NMMetered nm_setting_connection_get_metered(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_2
NMSettingConnectionLldp nm_setting_connection_get_lldp(NMSettingConnection *setting);

NM_AVAILABLE_IN_1_10
int nm_setting_connection_get_auth_retries(NMSettingConnection *setting);

NM_AVAILABLE_IN_1_12
NMSettingConnectionMdns nm_setting_connection_get_mdns(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_14
NMSettingConnectionLlmnr nm_setting_connection_get_llmnr(NMSettingConnection *setting);
NM_AVAILABLE_IN_1_34
NMSettingConnectionDnsOverTls nm_setting_connection_get_dns_over_tls(NMSettingConnection *setting);

NM_AVAILABLE_IN_1_20
gint32 nm_setting_connection_get_wait_device_timeout(NMSettingConnection *setting);

NM_AVAILABLE_IN_1_26
const char *nm_setting_connection_get_mud_url(NMSettingConnection *setting);

G_END_DECLS

#endif /* __NM_SETTING_CONNECTION_H__ */
