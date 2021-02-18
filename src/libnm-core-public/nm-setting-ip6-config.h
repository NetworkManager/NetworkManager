/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NM_SETTING_IP6_CONFIG_H__
#define __NM_SETTING_IP6_CONFIG_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
    #error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting-ip-config.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP6_CONFIG (nm_setting_ip6_config_get_type())
#define NM_SETTING_IP6_CONFIG(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6Config))
#define NM_SETTING_IP6_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_IP6CONFIG, NMSettingIP6ConfigClass))
#define NM_IS_SETTING_IP6_CONFIG(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_IS_SETTING_IP6_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_SETTING_IP6_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigClass))

#define NM_SETTING_IP6_CONFIG_SETTING_NAME "ipv6"

#define NM_SETTING_IP6_CONFIG_IP6_PRIVACY "ip6-privacy"

#define NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE "addr-gen-mode"

#define NM_SETTING_IP6_CONFIG_TOKEN "token"

#define NM_SETTING_IP6_CONFIG_DHCP_DUID "dhcp-duid"

#define NM_SETTING_IP6_CONFIG_RA_TIMEOUT "ra-timeout"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_IGNORE:
 *
 * IPv6 is not required or is handled by some other mechanism, and NetworkManager
 * should not configure IPv6 for this connection.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_IGNORE "ignore"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_AUTO:
 *
 * IPv6 configuration should be automatically determined via a method appropriate
 * for the hardware interface, ie router advertisements, DHCP, or PPP or some
 * other device-specific manner.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_AUTO "auto"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_DHCP:
 *
 * IPv6 configuration should be automatically determined via DHCPv6 only and
 * router advertisements should be ignored.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_DHCP "dhcp"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL:
 *
 * IPv6 configuration should be automatically configured for link-local-only
 * operation.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL "link-local"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_MANUAL:
 *
 * All necessary IPv6 configuration (addresses, prefix, DNS, etc) is specified
 * in the setting's properties.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_MANUAL "manual"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_SHARED:
 *
 * This connection specifies configuration that allows other computers to
 * connect through it to the default network (usually the Internet).  The
 * connection's interface will be assigned a private address, and router
 * advertisements, a caching DNS server, and Network Address Translation (NAT)
 * functionality will be started on this connection's interface to allow other
 * devices to connect through that interface to the default network. (not yet
 * supported for IPv6)
 */
#define NM_SETTING_IP6_CONFIG_METHOD_SHARED "shared"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_DISABLED:
 *
 * IPv6 is disabled for the connection.
 *
 * Since: 1.20
 */
#define NM_SETTING_IP6_CONFIG_METHOD_DISABLED "disabled"

/**
 * NMSettingIP6ConfigPrivacy:
 * @NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN: unknown or no value specified
 * @NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED: IPv6 Privacy Extensions are disabled
 * @NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR: IPv6 Privacy Extensions
 * are enabled, but public addresses are preferred over temporary addresses
 * @NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR: IPv6 Privacy Extensions
 * are enabled and temporary addresses are preferred over public addresses
 *
 * #NMSettingIP6ConfigPrivacy values indicate if and how IPv6 Privacy
 * Extensions are used (RFC4941).
 */
typedef enum {
    NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN            = -1,
    NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED           = 0,
    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR = 1,
    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR   = 2
} NMSettingIP6ConfigPrivacy;

/**
 * NMSettingIP6ConfigAddrGenMode:
 * @NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64: The Interface Identifier is derived
 * from the interface hardware address.
 * @NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY: The Interface Identifier
 * is created by using a cryptographically secure hash of a secret host-specific
 * key along with the connection identification and the network address as
 * specified by RFC7217.
 *
 * #NMSettingIP6ConfigAddrGenMode controls how the Interface Identifier for
 * RFC4862 Stateless Address Autoconfiguration is created.
 *
 * Since: 1.2
 */
typedef enum {
    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64          = 0,
    NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_STABLE_PRIVACY = 1,
} NMSettingIP6ConfigAddrGenMode;

/**
 * NMSettingIP6Config:
 *
 * IPv6 Settings
 */
struct _NMSettingIP6Config {
    NMSettingIPConfig parent;
};

typedef struct {
    NMSettingIPConfigClass parent;

    /*< private >*/
    gpointer padding[4];
} NMSettingIP6ConfigClass;

GType nm_setting_ip6_config_get_type(void);

NMSetting *nm_setting_ip6_config_new(void);

NMSettingIP6ConfigPrivacy nm_setting_ip6_config_get_ip6_privacy(NMSettingIP6Config *setting);
NM_AVAILABLE_IN_1_2
NMSettingIP6ConfigAddrGenMode nm_setting_ip6_config_get_addr_gen_mode(NMSettingIP6Config *setting);
NM_AVAILABLE_IN_1_4
const char *nm_setting_ip6_config_get_token(NMSettingIP6Config *setting);
NM_AVAILABLE_IN_1_12
const char *nm_setting_ip6_config_get_dhcp_duid(NMSettingIP6Config *setting);
NM_AVAILABLE_IN_1_24
gint32 nm_setting_ip6_config_get_ra_timeout(NMSettingIP6Config *setting);

G_END_DECLS

#endif /* __NM_SETTING_IP6_CONFIG_H__ */
