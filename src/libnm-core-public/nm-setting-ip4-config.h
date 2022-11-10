/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_IP4_CONFIG_H__
#define __NM_SETTING_IP4_CONFIG_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting-ip-config.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP4_CONFIG (nm_setting_ip4_config_get_type())
#define NM_SETTING_IP4_CONFIG(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4Config))
#define NM_SETTING_IP4_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_IP4CONFIG, NMSettingIP4ConfigClass))
#define NM_IS_SETTING_IP4_CONFIG(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_IS_SETTING_IP4_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_SETTING_IP4_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigClass))

#define NM_SETTING_IP4_CONFIG_SETTING_NAME "ipv4"

#define NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID               "dhcp-client-id"
#define NM_SETTING_IP4_CONFIG_DHCP_FQDN                    "dhcp-fqdn"
#define NM_SETTING_IP4_CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER "dhcp-vendor-class-identifier"
#define NM_SETTING_IP4_CONFIG_LINK_LOCAL                   "link-local"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_AUTO:
 *
 * IPv4 configuration should be automatically determined via a method appropriate
 * for the hardware interface, ie DHCP or PPP or some other device-specific
 * manner.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_AUTO "auto"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL:
 *
 * IPv4 configuration should be automatically configured for link-local-only
 * operation.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL "link-local"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_MANUAL:
 *
 * All necessary IPv4 configuration (addresses, prefix, DNS, etc) is specified
 * in the setting's properties.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_MANUAL "manual"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_SHARED:
 *
 * This connection specifies configuration that allows other computers to
 * connect through it to the default network (usually the Internet).  The
 * connection's interface will be assigned a private address, and a DHCP server,
 * caching DNS server, and Network Address Translation (NAT) functionality will
 * be started on this connection's interface to allow other devices to connect
 * through that interface to the default network.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_SHARED "shared"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_DISABLED:
 *
 * This connection does not use or require IPv4 address and it should be disabled.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_DISABLED "disabled"

/**
 * NMSettingIP4LinkLocal:
 * @NM_SETTING_IP4_LL_DEFAULT: Allow fallback to a globally configured default. If unspecified,
 *   fallback to "auto". Note that if "ipv4.method" is "disabled", this always implies link-local
 *   addresses disabled too.
 * @NM_SETTING_IP4_LL_AUTO: Special value which enables LL if "ipv4.method" is set to
 *   "link-local".
 * @NM_SETTING_IP4_LL_DISABLED: Disable IPv4 link-local protocol.
 * @NM_SETTING_IP4_LL_ENABLED: Enable the IPv4 link-local protocol regardless what other protocols
 * such as DHCP or manually assigned IP addresses might be active.
 *
 * #NMSettingIP4LinkLocal values indicate whether IPv4 link-local address protocol should be enabled.
 *
 * Since: 1.40
 */
typedef enum {
    NM_SETTING_IP4_LL_DEFAULT  = 0,
    NM_SETTING_IP4_LL_AUTO     = 1,
    NM_SETTING_IP4_LL_DISABLED = 2,
    NM_SETTING_IP4_LL_ENABLED  = 3,
} NMSettingIP4LinkLocal;

typedef struct _NMSettingIP4ConfigClass NMSettingIP4ConfigClass;

GType nm_setting_ip4_config_get_type(void);

NMSetting *nm_setting_ip4_config_new(void);

const char *nm_setting_ip4_config_get_dhcp_client_id(NMSettingIP4Config *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_ip4_config_get_dhcp_fqdn(NMSettingIP4Config *setting);

NM_AVAILABLE_IN_1_28
const char *nm_setting_ip4_config_get_dhcp_vendor_class_identifier(NMSettingIP4Config *setting);

NM_AVAILABLE_IN_1_42
NMSettingIP4LinkLocal nm_setting_ip4_config_get_link_local(NMSettingIP4Config *setting);

G_END_DECLS

#endif /* __NM_SETTING_IP4_CONFIG_H__ */
