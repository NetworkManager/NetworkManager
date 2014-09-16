/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NM_SETTING_IP6_CONFIG_H__
#define __NM_SETTING_IP6_CONFIG_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <arpa/inet.h>

#include "nm-setting.h"
#include "nm-setting-ip-config.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP6_CONFIG            (nm_setting_ip6_config_get_type ())
#define NM_SETTING_IP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6Config))
#define NM_SETTING_IP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IP6CONFIG, NMSettingIP6ConfigClass))
#define NM_IS_SETTING_IP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_IS_SETTING_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_SETTING_IP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigClass))

#define NM_SETTING_IP6_CONFIG_SETTING_NAME "ipv6"

#define NM_SETTING_IP6_CONFIG_METHOD             "method"
#define NM_SETTING_IP6_CONFIG_DNS                "dns"
#define NM_SETTING_IP6_CONFIG_DNS_SEARCH         "dns-search"
#define NM_SETTING_IP6_CONFIG_ADDRESSES          "addresses"
#define NM_SETTING_IP6_CONFIG_ROUTES             "routes"
#define NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES "ignore-auto-routes"
#define NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS    "ignore-auto-dns"
#define NM_SETTING_IP6_CONFIG_NEVER_DEFAULT      "never-default"
#define NM_SETTING_IP6_CONFIG_MAY_FAIL           "may-fail"
#define NM_SETTING_IP6_CONFIG_IP6_PRIVACY        "ip6-privacy"
#define NM_SETTING_IP6_CONFIG_DHCP_HOSTNAME      "dhcp-hostname"


/**
 * NM_SETTING_IP6_CONFIG_METHOD_IGNORE:
 *
 * IPv6 is not required or is handled by some other mechanism, and NetworkManager
 * should not configure IPv6 for this connection.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_IGNORE     "ignore"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_AUTO:
 *
 * IPv6 configuration should be automatically determined via a method appropriate
 * for the hardware interface, ie router advertisements, DHCP, or PPP or some
 * other device-specific manner.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_AUTO       "auto"

/**
 * NM_SETTING_IP6_CONFIG_METHOD_DHCP:
 *
 * IPv6 configuration should be automatically determined via DHCPv6 only and
 * router advertisements should be ignored.
 */
#define NM_SETTING_IP6_CONFIG_METHOD_DHCP       "dhcp"

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
#define NM_SETTING_IP6_CONFIG_METHOD_MANUAL     "manual"

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
#define NM_SETTING_IP6_CONFIG_METHOD_SHARED     "shared"

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
	NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN = -1,
	NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED = 0,
	NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR = 1,
	NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR = 2
} NMSettingIP6ConfigPrivacy;

struct _NMSettingIP6Config {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingIP6ConfigClass;

GType nm_setting_ip6_config_get_type (void);

NMSetting *            nm_setting_ip6_config_new                    (void);
const char *           nm_setting_ip6_config_get_method             (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_dns            (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dns                (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_dns                (NMSettingIP6Config *setting, const char *dns);
void                   nm_setting_ip6_config_remove_dns             (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_remove_dns_by_value    (NMSettingIP6Config *setting, const char *dns);
void                   nm_setting_ip6_config_clear_dns              (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_dns_searches       (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dns_search             (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_dns_search             (NMSettingIP6Config *setting, const char *dns_search);
void                   nm_setting_ip6_config_remove_dns_search          (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_remove_dns_search_by_value (NMSettingIP6Config *setting, const char *dns_search);
void                   nm_setting_ip6_config_clear_dns_searches         (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_addresses       (NMSettingIP6Config *setting);
NMIPAddress *          nm_setting_ip6_config_get_address             (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_address             (NMSettingIP6Config *setting, NMIPAddress *address);
void                   nm_setting_ip6_config_remove_address          (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_remove_address_by_value (NMSettingIP6Config *setting, NMIPAddress *address);
void                   nm_setting_ip6_config_clear_addresses         (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_routes         (NMSettingIP6Config *setting);
NMIPRoute *            nm_setting_ip6_config_get_route              (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_route              (NMSettingIP6Config *setting, NMIPRoute *route);
void                   nm_setting_ip6_config_remove_route           (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_remove_route_by_value  (NMSettingIP6Config *setting, NMIPRoute *route);
void                   nm_setting_ip6_config_clear_routes           (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_ignore_auto_routes (NMSettingIP6Config *setting);

gboolean               nm_setting_ip6_config_get_ignore_auto_dns    (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dhcp_hostname      (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_never_default      (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_may_fail           (NMSettingIP6Config *setting);
NMSettingIP6ConfigPrivacy nm_setting_ip6_config_get_ip6_privacy (NMSettingIP6Config *setting);

G_END_DECLS

#endif /* __NM_SETTING_IP6_CONFIG_H__ */
