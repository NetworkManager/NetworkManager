/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * David Cantrell <dcantrel@redhat.com>
 *
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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
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
#define NM_IS_SETTING_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_IP6_CONFIG))
#define NM_SETTING_IP6_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP6_CONFIG, NMSettingIP6ConfigClass))

#define NM_SETTING_IP6_CONFIG_SETTING_NAME "ipv6"

typedef enum
{
	NM_SETTING_IP6_CONFIG_ERROR_UNKNOWN = 0,
	NM_SETTING_IP6_CONFIG_ERROR_INVALID_PROPERTY,
	NM_SETTING_IP6_CONFIG_ERROR_MISSING_PROPERTY,
	NM_SETTING_IP6_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD
} NMSettingIP6ConfigError;

#define NM_TYPE_SETTING_IP6_CONFIG_ERROR (nm_setting_ip6_config_error_get_type ()) 
GType nm_setting_ip6_config_error_get_type (void);

#define NM_SETTING_IP6_CONFIG_ERROR nm_setting_ip6_config_error_quark ()
GQuark nm_setting_ip6_config_error_quark (void);

#define NM_SETTING_IP6_CONFIG_METHOD             "method"
#define NM_SETTING_IP6_CONFIG_DNS                "dns"
#define NM_SETTING_IP6_CONFIG_DNS_SEARCH         "dns-search"
#define NM_SETTING_IP6_CONFIG_ADDRESSES          "addresses"
#define NM_SETTING_IP6_CONFIG_ROUTES             "routes"
#define NM_SETTING_IP6_CONFIG_IGNORE_AUTO_ROUTES "ignore-auto-routes"
#define NM_SETTING_IP6_CONFIG_IGNORE_AUTO_DNS    "ignore-auto-dns"
#define NM_SETTING_IP6_CONFIG_NEVER_DEFAULT      "never-default"
#define NM_SETTING_IP6_CONFIG_MAY_FAIL           "may-fail"

#define NM_SETTING_IP6_CONFIG_METHOD_IGNORE     "ignore"
#define NM_SETTING_IP6_CONFIG_METHOD_AUTO       "auto"
#define NM_SETTING_IP6_CONFIG_METHOD_DHCP       "dhcp"
#define NM_SETTING_IP6_CONFIG_METHOD_LINK_LOCAL "link-local"
#define NM_SETTING_IP6_CONFIG_METHOD_MANUAL     "manual"
#define NM_SETTING_IP6_CONFIG_METHOD_SHARED     "shared"


typedef struct NMIP6Address NMIP6Address;

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
                                                   const struct in6_addr *gw);

typedef struct NMIP6Route NMIP6Route;

NMIP6Route *           nm_ip6_route_new          (void);
NMIP6Route *           nm_ip6_route_dup          (NMIP6Route *route);
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
void                   nm_setting_ip6_config_clear_dns              (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_dns_searches   (NMSettingIP6Config *setting);
const char *           nm_setting_ip6_config_get_dns_search         (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_dns_search         (NMSettingIP6Config *setting, const char *dns_search);
void                   nm_setting_ip6_config_remove_dns_search      (NMSettingIP6Config *setting, guint32 i);
void                   nm_setting_ip6_config_clear_dns_searches     (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_addresses      (NMSettingIP6Config *setting);
NMIP6Address *         nm_setting_ip6_config_get_address            (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_address            (NMSettingIP6Config *setting, NMIP6Address *address);
void                   nm_setting_ip6_config_remove_address         (NMSettingIP6Config *setting, guint32 i);
void                   nm_setting_ip6_config_clear_addresses        (NMSettingIP6Config *setting);

guint32                nm_setting_ip6_config_get_num_routes         (NMSettingIP6Config *setting);
NMIP6Route *           nm_setting_ip6_config_get_route              (NMSettingIP6Config *setting, guint32 i);
gboolean               nm_setting_ip6_config_add_route              (NMSettingIP6Config *setting, NMIP6Route *route);
void                   nm_setting_ip6_config_remove_route           (NMSettingIP6Config *setting, guint32 i);
void                   nm_setting_ip6_config_clear_routes           (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_ignore_auto_routes (NMSettingIP6Config *setting);

gboolean               nm_setting_ip6_config_get_ignore_auto_dns    (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_never_default      (NMSettingIP6Config *setting);
gboolean               nm_setting_ip6_config_get_may_fail           (NMSettingIP6Config *setting);

G_END_DECLS

#endif /* NM_SETTING_IP6_CONFIG_H */
