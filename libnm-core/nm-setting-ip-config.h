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
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_IP_CONFIG_H
#define NM_SETTING_IP_CONFIG_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

typedef struct NMIPAddress NMIPAddress;

GType        nm_ip_address_get_type            (void);

NMIPAddress *nm_ip_address_new                 (int family,
                                                const char  *addr,
                                                guint prefix,
                                                GError **error);
NMIPAddress *nm_ip_address_new_binary          (int family,
                                                gconstpointer addr,
                                                guint prefix,
                                                GError **error);

void         nm_ip_address_ref                 (NMIPAddress *address);
void         nm_ip_address_unref               (NMIPAddress *address);
gboolean     nm_ip_address_equal               (NMIPAddress *address,
                                                NMIPAddress *other);
NMIPAddress *nm_ip_address_dup                 (NMIPAddress *address);

int          nm_ip_address_get_family          (NMIPAddress *address);
const char  *nm_ip_address_get_address         (NMIPAddress *address);
void         nm_ip_address_set_address         (NMIPAddress *address,
                                                const char *addr);
void         nm_ip_address_get_address_binary  (NMIPAddress *address,
                                                gpointer addr);
void         nm_ip_address_set_address_binary  (NMIPAddress *address,
                                                gconstpointer addr);
guint        nm_ip_address_get_prefix          (NMIPAddress *address);
void         nm_ip_address_set_prefix          (NMIPAddress *address,
                                                guint prefix);

char       **nm_ip_address_get_attribute_names (NMIPAddress *address);
GVariant    *nm_ip_address_get_attribute       (NMIPAddress *address,
                                                const char  *name);
void         nm_ip_address_set_attribute       (NMIPAddress *address,
                                                const char  *name,
                                                GVariant    *value);


typedef struct NMIPRoute NMIPRoute;

GType        nm_ip_route_get_type            (void);

NMIPRoute   *nm_ip_route_new                 (int family,
                                              const char *dest,
                                              guint prefix,
                                              const char *next_hop,
                                              gint64 metric,
                                              GError **error);
NMIPRoute   *nm_ip_route_new_binary          (int family,
                                              gconstpointer dest,
                                              guint prefix,
                                              gconstpointer next_hop,
                                              gint64 metric,
                                              GError **error);

void         nm_ip_route_ref                 (NMIPRoute  *route);
void         nm_ip_route_unref               (NMIPRoute  *route);
gboolean     nm_ip_route_equal               (NMIPRoute  *route,
                                              NMIPRoute  *other);
NMIPRoute   *nm_ip_route_dup                 (NMIPRoute  *route);

int          nm_ip_route_get_family          (NMIPRoute  *route);
const char  *nm_ip_route_get_dest            (NMIPRoute  *route);
void         nm_ip_route_set_dest            (NMIPRoute  *route,
                                              const char *dest);
void         nm_ip_route_get_dest_binary     (NMIPRoute  *route,
                                              gpointer dest);
void         nm_ip_route_set_dest_binary     (NMIPRoute  *route,
                                              gconstpointer dest);
guint        nm_ip_route_get_prefix          (NMIPRoute  *route);
void         nm_ip_route_set_prefix          (NMIPRoute  *route,
                                              guint prefix);
const char  *nm_ip_route_get_next_hop        (NMIPRoute  *route);
void         nm_ip_route_set_next_hop        (NMIPRoute  *route,
                                              const char *next_hop);
gboolean     nm_ip_route_get_next_hop_binary (NMIPRoute  *route,
                                              gpointer next_hop);
void         nm_ip_route_set_next_hop_binary (NMIPRoute  *route,
                                              gconstpointer next_hop);
gint64       nm_ip_route_get_metric          (NMIPRoute  *route);
void         nm_ip_route_set_metric          (NMIPRoute  *route,
                                              gint64 metric);

char       **nm_ip_route_get_attribute_names (NMIPRoute   *route);
GVariant    *nm_ip_route_get_attribute       (NMIPRoute   *route,
                                              const char  *name);
void         nm_ip_route_set_attribute       (NMIPRoute   *route,
                                              const char  *name,
                                              GVariant    *value);


#define NM_TYPE_SETTING_IP_CONFIG            (nm_setting_ip_config_get_type ())
#define NM_SETTING_IP_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfig))
#define NM_SETTING_IP_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IPCONFIG, NMSettingIPConfigClass))
#define NM_IS_SETTING_IP_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP_CONFIG))
#define NM_IS_SETTING_IP_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_IP_CONFIG))
#define NM_SETTING_IP_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfigClass))

#define NM_SETTING_IP_CONFIG_METHOD             "method"
#define NM_SETTING_IP_CONFIG_DNS                "dns"
#define NM_SETTING_IP_CONFIG_DNS_SEARCH         "dns-search"
#define NM_SETTING_IP_CONFIG_DNS_OPTIONS        "dns-options"
#define NM_SETTING_IP_CONFIG_ADDRESSES          "addresses"
#define NM_SETTING_IP_CONFIG_GATEWAY            "gateway"
#define NM_SETTING_IP_CONFIG_ROUTES             "routes"
#define NM_SETTING_IP_CONFIG_ROUTE_METRIC       "route-metric"
#define NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES "ignore-auto-routes"
#define NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS    "ignore-auto-dns"
#define NM_SETTING_IP_CONFIG_DHCP_HOSTNAME      "dhcp-hostname"
#define NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME "dhcp-send-hostname"
#define NM_SETTING_IP_CONFIG_NEVER_DEFAULT      "never-default"
#define NM_SETTING_IP_CONFIG_MAY_FAIL           "may-fail"

#define NM_SETTING_DNS_OPTION_DEBUG                     "debug"
#define NM_SETTING_DNS_OPTION_NDOTS                     "ndots"
#define NM_SETTING_DNS_OPTION_TIMEOUT                   "timeout"
#define NM_SETTING_DNS_OPTION_ATTEMPTS                  "attempts"
#define NM_SETTING_DNS_OPTION_ROTATE                    "rotate"
#define NM_SETTING_DNS_OPTION_NO_CHECK_NAMES            "no-check-names"
#define NM_SETTING_DNS_OPTION_INET6                     "inet6"
#define NM_SETTING_DNS_OPTION_IP6_BYTESTRING            "ip6-bytestring"
#define NM_SETTING_DNS_OPTION_IP6_DOTINT                "ip6-dotint"
#define NM_SETTING_DNS_OPTION_NO_IP6_DOTINT             "no-ip6-dotint"
#define NM_SETTING_DNS_OPTION_EDNS0                     "edns0"
#define NM_SETTING_DNS_OPTION_SINGLE_REQUEST            "single-request"
#define NM_SETTING_DNS_OPTION_SINGLE_REQUEST_REOPEN     "single-request-reopen"
#define NM_SETTING_DNS_OPTION_NO_TLD_QUERY              "no-tld-query"

struct _NMSettingIPConfig {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	gpointer padding[8];
} NMSettingIPConfigClass;

GType nm_setting_ip_config_get_type (void);

const char   *nm_setting_ip_config_get_method                 (NMSettingIPConfig *setting);

guint         nm_setting_ip_config_get_num_dns                (NMSettingIPConfig *setting);
const char   *nm_setting_ip_config_get_dns                    (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_add_dns                    (NMSettingIPConfig *setting,
                                                               const char        *dns);
void          nm_setting_ip_config_remove_dns                 (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_remove_dns_by_value        (NMSettingIPConfig *setting,
                                                               const char        *dns);
void          nm_setting_ip_config_clear_dns                  (NMSettingIPConfig *setting);

guint         nm_setting_ip_config_get_num_dns_searches       (NMSettingIPConfig *setting);
const char   *nm_setting_ip_config_get_dns_search             (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_add_dns_search             (NMSettingIPConfig *setting,
                                                               const char        *dns_search);
void          nm_setting_ip_config_remove_dns_search          (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_remove_dns_search_by_value (NMSettingIPConfig *setting,
                                                               const char        *dns_search);
void          nm_setting_ip_config_clear_dns_searches         (NMSettingIPConfig *setting);

guint         nm_setting_ip_config_get_num_dns_options        (NMSettingIPConfig *setting);
gboolean      nm_setting_ip_config_has_dns_options            (NMSettingIPConfig *setting);
const char   *nm_setting_ip_config_get_dns_option             (NMSettingIPConfig *setting,
                                                               guint              idx);
gint          nm_setting_ip_config_next_valid_dns_option      (NMSettingIPConfig *setting,
                                                               guint              idx);
gboolean      nm_setting_ip_config_add_dns_option             (NMSettingIPConfig *setting,
                                                               const char        *dns_option);
void          nm_setting_ip_config_remove_dns_option          (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_remove_dns_option_by_value (NMSettingIPConfig *setting,
                                                               const char        *dns_option);
void          nm_setting_ip_config_clear_dns_options          (NMSettingIPConfig *setting, gboolean is_set);

guint         nm_setting_ip_config_get_num_addresses          (NMSettingIPConfig *setting);
NMIPAddress  *nm_setting_ip_config_get_address                (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_add_address                (NMSettingIPConfig *setting,
                                                               NMIPAddress       *address);
void          nm_setting_ip_config_remove_address             (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_remove_address_by_value    (NMSettingIPConfig *setting,
                                                               NMIPAddress       *address);
void          nm_setting_ip_config_clear_addresses            (NMSettingIPConfig *setting);

const char   *nm_setting_ip_config_get_gateway                (NMSettingIPConfig *setting);

guint         nm_setting_ip_config_get_num_routes             (NMSettingIPConfig *setting);
NMIPRoute    *nm_setting_ip_config_get_route                  (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_add_route                  (NMSettingIPConfig *setting,
                                                               NMIPRoute         *route);
void          nm_setting_ip_config_remove_route               (NMSettingIPConfig *setting,
                                                               int                idx);
gboolean      nm_setting_ip_config_remove_route_by_value      (NMSettingIPConfig *setting,
                                                               NMIPRoute         *route);
void          nm_setting_ip_config_clear_routes               (NMSettingIPConfig *setting);

gint64        nm_setting_ip_config_get_route_metric           (NMSettingIPConfig *setting);

gboolean      nm_setting_ip_config_get_ignore_auto_routes     (NMSettingIPConfig *setting);
gboolean      nm_setting_ip_config_get_ignore_auto_dns        (NMSettingIPConfig *setting);

const char   *nm_setting_ip_config_get_dhcp_hostname          (NMSettingIPConfig *setting);
gboolean      nm_setting_ip_config_get_dhcp_send_hostname     (NMSettingIPConfig *setting);

gboolean      nm_setting_ip_config_get_never_default          (NMSettingIPConfig *setting);
gboolean      nm_setting_ip_config_get_may_fail               (NMSettingIPConfig *setting);

G_END_DECLS

#endif /* NM_SETTING_IP_CONFIG_H */
