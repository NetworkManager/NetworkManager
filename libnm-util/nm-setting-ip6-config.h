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

#ifndef NM_SETTING_IP6_CONFIG_H
#define NM_SETTING_IP6_CONFIG_H

#include <arpa/inet.h>

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP6_CONFIG            (nm_setting_ip6_config_get_type ())
#define NM_SETTING_IP6_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6Config))
#define NM_SETTING_IP6_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IP6CONFIG, NMSettingIP6ConfigClass))
#define NM_IS_SETTING_IP6_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_IS_SETTING_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_SETTING_IP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigClass))

#define NM_SETTING_IP6_CONFIG_SETTING_NAME "ipv6"

/**
 * NMSettingIP6ConfigError:
 * @NM_SETTING_IP6_CONFIG_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 * @NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD: the property's value is
 * not valid with the given IPv6 method
 */
typedef enum {
	NM_SETTING_IP6_CONFIG_ERROR_UNKNOWN = 0,           /*< nick=UnknownError >*/
	NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,      /*< nick=InvalidProperty >*/
	NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,      /*< nick=MissingProperty >*/
	NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD /*< nick=NotAllowedForMethod >*/
} NMSettingIP6ConfigError;

#define NM_SETTING_IP6_CONFIG_ERROR nm_setting_ip6_config_error_quark ()
GQuark nm_setting_ip6_config_error_quark (void);

#define NM_SETTING_IP6_CONFIG_METHOD             "method"
#define NM_SETTING_IP6_CONFIG_DNS                "dns"
#define NM_SETTING_IP6_CONFIG_DNS_SEARCH         "dns-search"
#define NM_SETTING_IP6_CONFIG_ADDRESSES          "addresses"
#define NM_SETTING_IP6_CONFIG_ROUTES             "routes"
#define NM_SETTING_IP6_CONFIG_ROUTE_METRIC       "route-metric"
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


typedef struct NMIP6Address NMIP6Address;

GType nm_ip6_address_get_type (void);

NMIP6Address *         nm_ip6_address_new         (void);
NMIP6Address *         nm_ip6_address_dup         (NMIP6Address *source);
void                   nm_ip6_address_ref         (NMIP6Address *address);
void                   nm_ip6_address_unref       (NMIP6Address *address);
/* Return TRUE if addresses are identical */
gboolean               nm_ip6_address_compare     (NMIP6Address *address, NMIP6Address *other);

const struct in6_addr *nm_ip6_address_get_address (NMIP6Address *address);
void                   nm_ip6_address_set_address (NMIP6Address *address,
                                                   const struct in6_addr *addr);

guint32                nm_ip6_address_get_prefix  (NMIP6Address *address);
void                   nm_ip6_address_set_prefix  (NMIP6Address *address,
                                                   guint32 prefix);

const struct in6_addr *nm_ip6_address_get_gateway (NMIP6Address *address);
void                   nm_ip6_address_set_gateway (NMIP6Address *address,
                                                   const struct in6_addr *gateway);

typedef struct NMIP6Route NMIP6Route;

GType nm_ip6_route_get_type (void);

NMIP6Route *           nm_ip6_route_new          (void);
NMIP6Route *           nm_ip6_route_dup          (NMIP6Route *source);
void                   nm_ip6_route_ref          (NMIP6Route *route);
void                   nm_ip6_route_unref        (NMIP6Route *route);
/* Return TRUE if routes are identical */
gboolean               nm_ip6_route_compare      (NMIP6Route *route, NMIP6Route *other);

const struct in6_addr *nm_ip6_route_get_dest     (NMIP6Route *route);
void                   nm_ip6_route_set_dest     (NMIP6Route *route,
                                                  const struct in6_addr *dest);

guint32                nm_ip6_route_get_prefix   (NMIP6Route *route);
void                   nm_ip6_route_set_prefix   (NMIP6Route *route,
                                                  guint32 prefix);

const struct in6_addr *nm_ip6_route_get_next_hop (NMIP6Route *route);
void                   nm_ip6_route_set_next_hop (NMIP6Route *route,
                                                  const struct in6_addr *next_hop);

guint32                nm_ip6_route_get_metric   (NMIP6Route *route);
void                   nm_ip6_route_set_metric   (NMIP6Route *route,
                                                  guint32 metric);

typedef struct {
	NMSetting parent;
} NMSettingIP6Config;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingIP6ConfigClass;

GType nm_setting_ip6_config_get_type (void);

NMSetting *            nm_setting_ip6_config_new                    (void);
const char *           nm_setting_ip6_config_get_method             (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_dns            (NMSettingIP6Config *setting);
const struct in6_addr *nm_setting_ip6_config_get_dns                (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_dns                (NMSettingIP6Config *setting, const struct in6_addr *dns);
void                   nm_setting_ip6_config_remove_dns             (NMSettingIP6Config *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean               nm_setting_ip6_config_remove_dns_by_value    (NMSettingIP6Config *setting, const struct in6_addr *dns);
void                   nm_setting_ip6_config_clear_dns              (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_dns_searches       (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dns_search             (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_dns_search             (NMSettingIP6Config *setting, const char *dns_search);
void                   nm_setting_ip6_config_remove_dns_search          (NMSettingIP6Config *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean               nm_setting_ip6_config_remove_dns_search_by_value (NMSettingIP6Config *setting, const char *dns_search);
void                   nm_setting_ip6_config_clear_dns_searches         (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_addresses       (NMSettingIP6Config *setting);
NMIP6Address *         nm_setting_ip6_config_get_address             (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_address             (NMSettingIP6Config *setting, NMIP6Address *address);
void                   nm_setting_ip6_config_remove_address          (NMSettingIP6Config *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean               nm_setting_ip6_config_remove_address_by_value (NMSettingIP6Config *setting, NMIP6Address *address);
void                   nm_setting_ip6_config_clear_addresses         (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_routes         (NMSettingIP6Config *setting);
NMIP6Route *           nm_setting_ip6_config_get_route              (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_route              (NMSettingIP6Config *setting, NMIP6Route *route);
void                   nm_setting_ip6_config_remove_route           (NMSettingIP6Config *setting, guint32 i);
NM_AVAILABLE_IN_0_9_10
gboolean               nm_setting_ip6_config_remove_route_by_value  (NMSettingIP6Config *setting, NMIP6Route *route);
void                   nm_setting_ip6_config_clear_routes           (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_ignore_auto_routes (NMSettingIP6Config *setting);

NM_AVAILABLE_IN_1_0
gint64                 nm_setting_ip6_config_get_route_metric       (NMSettingIP6Config *setting);

gboolean               nm_setting_ip6_config_get_ignore_auto_dns    (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dhcp_hostname      (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_never_default      (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_may_fail           (NMSettingIP6Config *setting);
NMSettingIP6ConfigPrivacy nm_setting_ip6_config_get_ip6_privacy (NMSettingIP6Config *setting);

G_END_DECLS

#endif /* NM_SETTING_IP6_CONFIG_H */
