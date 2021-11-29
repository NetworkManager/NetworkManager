/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_IP_CONFIG_H
#define NM_SETTING_IP_CONFIG_H

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-utils.h"

G_BEGIN_DECLS

#define NM_IP_ADDRESS_ATTRIBUTE_LABEL "label"

/**
 * NMIPAddressCmpFlags:
 * @NM_IP_ADDRESS_CMP_FLAGS_NONE: no flags.
 * @NM_IP_ADDRESS_CMP_FLAGS_WITH_ATTRS: when comparing two addresses,
 *   also consider their attributes. Warning: note that attributes are GVariants
 *   and they don't have a total order. In other words, if the address differs only
 *   by their attributes, the returned compare order is not total. In that case,
 *   the return value merely indicates equality (zero) or inequality.
 *
 * Compare flags for nm_ip_address_cmp_full().
 *
 * Since: 1.22
 */
typedef enum { /*< flags >*/
               NM_IP_ADDRESS_CMP_FLAGS_NONE       = 0,
               NM_IP_ADDRESS_CMP_FLAGS_WITH_ATTRS = 0x1,
} NMIPAddressCmpFlags;

typedef struct NMIPAddress NMIPAddress;

GType nm_ip_address_get_type(void);

NMIPAddress *nm_ip_address_new(int family, const char *addr, guint prefix, GError **error);
NMIPAddress *nm_ip_address_new_binary(int family, gconstpointer addr, guint prefix, GError **error);

void     nm_ip_address_ref(NMIPAddress *address);
void     nm_ip_address_unref(NMIPAddress *address);
gboolean nm_ip_address_equal(NMIPAddress *address, NMIPAddress *other);
NM_AVAILABLE_IN_1_22
int
nm_ip_address_cmp_full(const NMIPAddress *a, const NMIPAddress *b, NMIPAddressCmpFlags cmp_flags);

NM_AVAILABLE_IN_1_32
NMIPAddress *nm_ip_address_dup(NMIPAddress *address);

int         nm_ip_address_get_family(NMIPAddress *address);
const char *nm_ip_address_get_address(NMIPAddress *address);
void        nm_ip_address_set_address(NMIPAddress *address, const char *addr);
void        nm_ip_address_get_address_binary(NMIPAddress *address, gpointer addr);
void        nm_ip_address_set_address_binary(NMIPAddress *address, gconstpointer addr);
guint       nm_ip_address_get_prefix(NMIPAddress *address);
void        nm_ip_address_set_prefix(NMIPAddress *address, guint prefix);

char    **nm_ip_address_get_attribute_names(NMIPAddress *address);
GVariant *nm_ip_address_get_attribute(NMIPAddress *address, const char *name);
void      nm_ip_address_set_attribute(NMIPAddress *address, const char *name, GVariant *value);

typedef struct NMIPRoute NMIPRoute;

GType nm_ip_route_get_type(void);

NMIPRoute *nm_ip_route_new(int         family,
                           const char *dest,
                           guint       prefix,
                           const char *next_hop,
                           gint64      metric,
                           GError    **error);
NMIPRoute *nm_ip_route_new_binary(int           family,
                                  gconstpointer dest,
                                  guint         prefix,
                                  gconstpointer next_hop,
                                  gint64        metric,
                                  GError      **error);

void     nm_ip_route_ref(NMIPRoute *route);
void     nm_ip_route_unref(NMIPRoute *route);
gboolean nm_ip_route_equal(NMIPRoute *route, NMIPRoute *other);

enum { /*< flags >*/
       NM_IP_ROUTE_EQUAL_CMP_FLAGS_NONE       = 0,
       NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS = 0x1,
};

NM_AVAILABLE_IN_1_10
gboolean nm_ip_route_equal_full(NMIPRoute *route, NMIPRoute *other, guint cmp_flags);

NM_AVAILABLE_IN_1_32
NMIPRoute *nm_ip_route_dup(NMIPRoute *route);

int         nm_ip_route_get_family(NMIPRoute *route);
const char *nm_ip_route_get_dest(NMIPRoute *route);
void        nm_ip_route_set_dest(NMIPRoute *route, const char *dest);
void        nm_ip_route_get_dest_binary(NMIPRoute *route, gpointer dest);
void        nm_ip_route_set_dest_binary(NMIPRoute *route, gconstpointer dest);
guint       nm_ip_route_get_prefix(NMIPRoute *route);
void        nm_ip_route_set_prefix(NMIPRoute *route, guint prefix);
const char *nm_ip_route_get_next_hop(NMIPRoute *route);
void        nm_ip_route_set_next_hop(NMIPRoute *route, const char *next_hop);
gboolean    nm_ip_route_get_next_hop_binary(NMIPRoute *route, gpointer next_hop);
void        nm_ip_route_set_next_hop_binary(NMIPRoute *route, gconstpointer next_hop);
gint64      nm_ip_route_get_metric(NMIPRoute *route);
void        nm_ip_route_set_metric(NMIPRoute *route, gint64 metric);

char    **nm_ip_route_get_attribute_names(NMIPRoute *route);
GVariant *nm_ip_route_get_attribute(NMIPRoute *route, const char *name);
void      nm_ip_route_set_attribute(NMIPRoute *route, const char *name, GVariant *value);
NM_AVAILABLE_IN_1_8
const NMVariantAttributeSpec *const *nm_ip_route_get_variant_attribute_spec(void);
NM_AVAILABLE_IN_1_8
gboolean nm_ip_route_attribute_validate(const char *name,
                                        GVariant   *value,
                                        int         family,
                                        gboolean   *known,
                                        GError    **error);

#define NM_IP_ROUTE_ATTRIBUTE_CWND          "cwnd"
#define NM_IP_ROUTE_ATTRIBUTE_FROM          "from"
#define NM_IP_ROUTE_ATTRIBUTE_INITCWND      "initcwnd"
#define NM_IP_ROUTE_ATTRIBUTE_INITRWND      "initrwnd"
#define NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND     "lock-cwnd"
#define NM_IP_ROUTE_ATTRIBUTE_LOCK_INITCWND "lock-initcwnd"
#define NM_IP_ROUTE_ATTRIBUTE_LOCK_INITRWND "lock-initrwnd"
#define NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU      "lock-mtu"
#define NM_IP_ROUTE_ATTRIBUTE_LOCK_WINDOW   "lock-window"
#define NM_IP_ROUTE_ATTRIBUTE_MTU           "mtu"
#define NM_IP_ROUTE_ATTRIBUTE_ONLINK        "onlink"
#define NM_IP_ROUTE_ATTRIBUTE_SCOPE         "scope"
#define NM_IP_ROUTE_ATTRIBUTE_SRC           "src"
#define NM_IP_ROUTE_ATTRIBUTE_TABLE         "table"
#define NM_IP_ROUTE_ATTRIBUTE_TOS           "tos"
#define NM_IP_ROUTE_ATTRIBUTE_TYPE          "type"
#define NM_IP_ROUTE_ATTRIBUTE_WINDOW        "window"

/*****************************************************************************/

typedef struct NMIPRoutingRule NMIPRoutingRule;

NM_AVAILABLE_IN_1_18
GType nm_ip_routing_rule_get_type(void);

NM_AVAILABLE_IN_1_18
NMIPRoutingRule *nm_ip_routing_rule_new(int addr_family);

NM_AVAILABLE_IN_1_18
NMIPRoutingRule *nm_ip_routing_rule_new_clone(const NMIPRoutingRule *rule);

NM_AVAILABLE_IN_1_18
NMIPRoutingRule *nm_ip_routing_rule_ref(NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_unref(NMIPRoutingRule *self);

NM_AVAILABLE_IN_1_18
gboolean nm_ip_routing_rule_is_sealed(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_seal(NMIPRoutingRule *self);

NM_AVAILABLE_IN_1_18
int nm_ip_routing_rule_get_addr_family(const NMIPRoutingRule *self);

NM_AVAILABLE_IN_1_18
gboolean nm_ip_routing_rule_get_invert(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_invert(NMIPRoutingRule *self, gboolean invert);

NM_AVAILABLE_IN_1_18
gint64 nm_ip_routing_rule_get_priority(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_priority(NMIPRoutingRule *self, gint64 priority);

NM_AVAILABLE_IN_1_18
guint8 nm_ip_routing_rule_get_tos(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_tos(NMIPRoutingRule *self, guint8 tos);

NM_AVAILABLE_IN_1_18
guint8 nm_ip_routing_rule_get_ipproto(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_ipproto(NMIPRoutingRule *self, guint8 ipproto);

NM_AVAILABLE_IN_1_18
guint16 nm_ip_routing_rule_get_source_port_start(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
guint16 nm_ip_routing_rule_get_source_port_end(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_source_port(NMIPRoutingRule *self, guint16 start, guint16 end);

NM_AVAILABLE_IN_1_18
guint16 nm_ip_routing_rule_get_destination_port_start(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
guint16 nm_ip_routing_rule_get_destination_port_end(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_destination_port(NMIPRoutingRule *self, guint16 start, guint16 end);

NM_AVAILABLE_IN_1_18
guint32 nm_ip_routing_rule_get_fwmark(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
guint32 nm_ip_routing_rule_get_fwmask(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_fwmark(NMIPRoutingRule *self, guint32 fwmark, guint32 fwmask);

NM_AVAILABLE_IN_1_18
guint8 nm_ip_routing_rule_get_from_len(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
const char *nm_ip_routing_rule_get_from(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_from(NMIPRoutingRule *self, const char *from, guint8 len);

NM_AVAILABLE_IN_1_18
guint8 nm_ip_routing_rule_get_to_len(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
const char *nm_ip_routing_rule_get_to(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_to(NMIPRoutingRule *self, const char *to, guint8 len);

NM_AVAILABLE_IN_1_18
const char *nm_ip_routing_rule_get_iifname(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_iifname(NMIPRoutingRule *self, const char *iifname);

NM_AVAILABLE_IN_1_18
const char *nm_ip_routing_rule_get_oifname(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_oifname(NMIPRoutingRule *self, const char *oifname);

NM_AVAILABLE_IN_1_18
guint8 nm_ip_routing_rule_get_action(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_action(NMIPRoutingRule *self, guint8 action);

NM_AVAILABLE_IN_1_18
guint32 nm_ip_routing_rule_get_table(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_18
void nm_ip_routing_rule_set_table(NMIPRoutingRule *self, guint32 table);

NM_AVAILABLE_IN_1_20
gint32 nm_ip_routing_rule_get_suppress_prefixlength(const NMIPRoutingRule *self);
NM_AVAILABLE_IN_1_20
void nm_ip_routing_rule_set_suppress_prefixlength(NMIPRoutingRule *self,
                                                  gint32           suppress_prefixlength);

NM_AVAILABLE_IN_1_34
gboolean nm_ip_routing_rule_get_uid_range(const NMIPRoutingRule *self,
                                          guint32               *out_range_start,
                                          guint32               *out_range_end);
NM_AVAILABLE_IN_1_34
void nm_ip_routing_rule_set_uid_range(NMIPRoutingRule *self,
                                      guint32          uid_range_start,
                                      guint32          uid_range_end);

NM_AVAILABLE_IN_1_18
int nm_ip_routing_rule_cmp(const NMIPRoutingRule *rule, const NMIPRoutingRule *other);

NM_AVAILABLE_IN_1_18
gboolean nm_ip_routing_rule_validate(const NMIPRoutingRule *self, GError **error);

/**
 * NMIPRoutingRuleAsStringFlags:
 * @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE: no flags selected.
 * @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET: whether to allow parsing
 *   IPv4 addresses.
 * @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6: whether to allow parsing
 *   IPv6 addresses. If both @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET and
 *   @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6 are unset, it's the same
 *   as setting them both.
 * @NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE: if set, ensure that the
 *   rule verfies or fail.
 *
 * Since: 1.18
 */
typedef enum { /*< flags >*/
               NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE = 0,

               NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET  = 0x1,
               NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6 = 0x2,
               NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE = 0x4,
} NMIPRoutingRuleAsStringFlags;

NM_AVAILABLE_IN_1_18
NMIPRoutingRule *nm_ip_routing_rule_from_string(const char                  *str,
                                                NMIPRoutingRuleAsStringFlags to_string_flags,
                                                GHashTable                  *extra_args,
                                                GError                     **error);

NM_AVAILABLE_IN_1_18
char *nm_ip_routing_rule_to_string(const NMIPRoutingRule       *self,
                                   NMIPRoutingRuleAsStringFlags to_string_flags,
                                   GHashTable                  *extra_args,
                                   GError                     **error);

/*****************************************************************************/

#define NM_TYPE_SETTING_IP_CONFIG (nm_setting_ip_config_get_type())
#define NM_SETTING_IP_CONFIG(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfig))
#define NM_SETTING_IP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfigClass))
#define NM_IS_SETTING_IP_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_IP_CONFIG))
#define NM_IS_SETTING_IP_CONFIG_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_IP_CONFIG))
#define NM_SETTING_IP_CONFIG_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfigClass))

#define NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX 30000

#define NM_SETTING_IP_CONFIG_METHOD              "method"
#define NM_SETTING_IP_CONFIG_DNS                 "dns"
#define NM_SETTING_IP_CONFIG_DNS_SEARCH          "dns-search"
#define NM_SETTING_IP_CONFIG_DNS_OPTIONS         "dns-options"
#define NM_SETTING_IP_CONFIG_DNS_PRIORITY        "dns-priority"
#define NM_SETTING_IP_CONFIG_ADDRESSES           "addresses"
#define NM_SETTING_IP_CONFIG_GATEWAY             "gateway"
#define NM_SETTING_IP_CONFIG_ROUTES              "routes"
#define NM_SETTING_IP_CONFIG_ROUTE_METRIC        "route-metric"
#define NM_SETTING_IP_CONFIG_ROUTE_TABLE         "route-table"
#define NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES  "ignore-auto-routes"
#define NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS     "ignore-auto-dns"
#define NM_SETTING_IP_CONFIG_DHCP_HOSTNAME       "dhcp-hostname"
#define NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME  "dhcp-send-hostname"
#define NM_SETTING_IP_CONFIG_DHCP_HOSTNAME_FLAGS "dhcp-hostname-flags"
#define NM_SETTING_IP_CONFIG_NEVER_DEFAULT       "never-default"
#define NM_SETTING_IP_CONFIG_MAY_FAIL            "may-fail"
#define NM_SETTING_IP_CONFIG_DAD_TIMEOUT         "dad-timeout"
#define NM_SETTING_IP_CONFIG_DHCP_TIMEOUT        "dhcp-timeout"
#define NM_SETTING_IP_CONFIG_REQUIRED_TIMEOUT    "required-timeout"
#define NM_SETTING_IP_CONFIG_DHCP_IAID           "dhcp-iaid"
#define NM_SETTING_IP_CONFIG_DHCP_REJECT_SERVERS "dhcp-reject-servers"

/* these are not real GObject properties. */
#define NM_SETTING_IP_CONFIG_ROUTING_RULES "routing-rules"

#define NM_SETTING_DNS_OPTION_DEBUG                 "debug"
#define NM_SETTING_DNS_OPTION_NDOTS                 "ndots"
#define NM_SETTING_DNS_OPTION_TIMEOUT               "timeout"
#define NM_SETTING_DNS_OPTION_ATTEMPTS              "attempts"
#define NM_SETTING_DNS_OPTION_ROTATE                "rotate"
#define NM_SETTING_DNS_OPTION_NO_CHECK_NAMES        "no-check-names"
#define NM_SETTING_DNS_OPTION_INET6                 "inet6"
#define NM_SETTING_DNS_OPTION_IP6_BYTESTRING        "ip6-bytestring"
#define NM_SETTING_DNS_OPTION_IP6_DOTINT            "ip6-dotint"
#define NM_SETTING_DNS_OPTION_NO_IP6_DOTINT         "no-ip6-dotint"
#define NM_SETTING_DNS_OPTION_EDNS0                 "edns0"
#define NM_SETTING_DNS_OPTION_SINGLE_REQUEST        "single-request"
#define NM_SETTING_DNS_OPTION_SINGLE_REQUEST_REOPEN "single-request-reopen"
#define NM_SETTING_DNS_OPTION_NO_TLD_QUERY          "no-tld-query"
#define NM_SETTING_DNS_OPTION_USE_VC                "use-vc"
#define NM_SETTING_DNS_OPTION_NO_RELOAD             "no-reload"
#define NM_SETTING_DNS_OPTION_TRUST_AD              "trust-ad"

typedef struct _NMSettingIPConfigClass NMSettingIPConfigClass;

/**
 * NMDhcpHostnameFlags:
 * @NM_DHCP_HOSTNAME_FLAG_NONE: no flag set. The default value from
 *   Networkmanager global configuration is used. If such value is unset
 *   or still zero, the DHCP request will use standard FQDN flags, i.e.
 *   %NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE and
 *   %NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED for IPv4 and
 *   %NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE for IPv6.
 * @NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE: whether the server should
 *   do the A RR (FQDN-to-address) DNS updates.
 * @NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED: if set, the FQDN is encoded
 *   using canonical wire format. Otherwise it uses the deprecated
 *   ASCII encoding. This flag is allowed only for DHCPv4.
 * @NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE: when not set, request the
 *   server to perform updates (the PTR RR and possibly the A RR
 *   based on the %NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE flag). If
 *   this is set, the %NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE flag
 *   should be cleared.
 * @NM_DHCP_HOSTNAME_FLAG_FQDN_CLEAR_FLAGS: when set, no FQDN flags are
 *   sent in the DHCP FQDN option. When cleared and all other FQDN
 *   flags are zero, standard FQDN flags are sent. This flag is
 *   incompatible with any other FQDN flag.
 *
 * #NMDhcpHostnameFlags describe flags related to the DHCP hostname and
 * FQDN.
 *
 * Since: 1.22
 */
typedef enum { /*< flags >*/
               NM_DHCP_HOSTNAME_FLAG_NONE = 0x0,

               NM_DHCP_HOSTNAME_FLAG_FQDN_SERV_UPDATE = 0x1,
               NM_DHCP_HOSTNAME_FLAG_FQDN_ENCODED     = 0x2,
               NM_DHCP_HOSTNAME_FLAG_FQDN_NO_UPDATE   = 0x4,

               NM_DHCP_HOSTNAME_FLAG_FQDN_CLEAR_FLAGS = 0x8,

} NMDhcpHostnameFlags;

GType nm_setting_ip_config_get_type(void);

const char *nm_setting_ip_config_get_method(NMSettingIPConfig *setting);

guint       nm_setting_ip_config_get_num_dns(NMSettingIPConfig *setting);
const char *nm_setting_ip_config_get_dns(NMSettingIPConfig *setting, int idx);
gboolean    nm_setting_ip_config_add_dns(NMSettingIPConfig *setting, const char *dns);
void        nm_setting_ip_config_remove_dns(NMSettingIPConfig *setting, int idx);
gboolean    nm_setting_ip_config_remove_dns_by_value(NMSettingIPConfig *setting, const char *dns);
void        nm_setting_ip_config_clear_dns(NMSettingIPConfig *setting);

guint       nm_setting_ip_config_get_num_dns_searches(NMSettingIPConfig *setting);
const char *nm_setting_ip_config_get_dns_search(NMSettingIPConfig *setting, int idx);
gboolean    nm_setting_ip_config_add_dns_search(NMSettingIPConfig *setting, const char *dns_search);
void        nm_setting_ip_config_remove_dns_search(NMSettingIPConfig *setting, int idx);
gboolean    nm_setting_ip_config_remove_dns_search_by_value(NMSettingIPConfig *setting,
                                                            const char        *dns_search);
void        nm_setting_ip_config_clear_dns_searches(NMSettingIPConfig *setting);

guint       nm_setting_ip_config_get_num_dns_options(NMSettingIPConfig *setting);
gboolean    nm_setting_ip_config_has_dns_options(NMSettingIPConfig *setting);
const char *nm_setting_ip_config_get_dns_option(NMSettingIPConfig *setting, guint idx);
gboolean    nm_setting_ip_config_add_dns_option(NMSettingIPConfig *setting, const char *dns_option);
void        nm_setting_ip_config_remove_dns_option(NMSettingIPConfig *setting, int idx);
gboolean    nm_setting_ip_config_remove_dns_option_by_value(NMSettingIPConfig *setting,
                                                            const char        *dns_option);
void        nm_setting_ip_config_clear_dns_options(NMSettingIPConfig *setting, gboolean is_set);

NM_AVAILABLE_IN_1_4
int nm_setting_ip_config_get_dns_priority(NMSettingIPConfig *setting);

guint        nm_setting_ip_config_get_num_addresses(NMSettingIPConfig *setting);
NMIPAddress *nm_setting_ip_config_get_address(NMSettingIPConfig *setting, int idx);
gboolean     nm_setting_ip_config_add_address(NMSettingIPConfig *setting, NMIPAddress *address);
void         nm_setting_ip_config_remove_address(NMSettingIPConfig *setting, int idx);
gboolean     nm_setting_ip_config_remove_address_by_value(NMSettingIPConfig *setting,
                                                          NMIPAddress       *address);
void         nm_setting_ip_config_clear_addresses(NMSettingIPConfig *setting);

const char *nm_setting_ip_config_get_gateway(NMSettingIPConfig *setting);

guint      nm_setting_ip_config_get_num_routes(NMSettingIPConfig *setting);
NMIPRoute *nm_setting_ip_config_get_route(NMSettingIPConfig *setting, int idx);
gboolean   nm_setting_ip_config_add_route(NMSettingIPConfig *setting, NMIPRoute *route);
void       nm_setting_ip_config_remove_route(NMSettingIPConfig *setting, int idx);
gboolean   nm_setting_ip_config_remove_route_by_value(NMSettingIPConfig *setting, NMIPRoute *route);
void       nm_setting_ip_config_clear_routes(NMSettingIPConfig *setting);

gint64 nm_setting_ip_config_get_route_metric(NMSettingIPConfig *setting);

NM_AVAILABLE_IN_1_10
guint32 nm_setting_ip_config_get_route_table(NMSettingIPConfig *setting);

NM_AVAILABLE_IN_1_18
guint nm_setting_ip_config_get_num_routing_rules(NMSettingIPConfig *setting);
NM_AVAILABLE_IN_1_18
NMIPRoutingRule *nm_setting_ip_config_get_routing_rule(NMSettingIPConfig *setting, guint idx);
NM_AVAILABLE_IN_1_18
void nm_setting_ip_config_add_routing_rule(NMSettingIPConfig *setting,
                                           NMIPRoutingRule   *routing_rule);
NM_AVAILABLE_IN_1_18
void nm_setting_ip_config_remove_routing_rule(NMSettingIPConfig *setting, guint idx);
NM_AVAILABLE_IN_1_18
void nm_setting_ip_config_clear_routing_rules(NMSettingIPConfig *setting);

gboolean nm_setting_ip_config_get_ignore_auto_routes(NMSettingIPConfig *setting);
gboolean nm_setting_ip_config_get_ignore_auto_dns(NMSettingIPConfig *setting);

const char *nm_setting_ip_config_get_dhcp_hostname(NMSettingIPConfig *setting);
gboolean    nm_setting_ip_config_get_dhcp_send_hostname(NMSettingIPConfig *setting);

gboolean nm_setting_ip_config_get_never_default(NMSettingIPConfig *setting);
gboolean nm_setting_ip_config_get_may_fail(NMSettingIPConfig *setting);
NM_AVAILABLE_IN_1_2
int nm_setting_ip_config_get_dad_timeout(NMSettingIPConfig *setting);
NM_AVAILABLE_IN_1_2
int nm_setting_ip_config_get_dhcp_timeout(NMSettingIPConfig *setting);
NM_AVAILABLE_IN_1_34
int nm_setting_ip_config_get_required_timeout(NMSettingIPConfig *setting);
NM_AVAILABLE_IN_1_22
const char *nm_setting_ip_config_get_dhcp_iaid(NMSettingIPConfig *setting);

NM_AVAILABLE_IN_1_22
NMDhcpHostnameFlags nm_setting_ip_config_get_dhcp_hostname_flags(NMSettingIPConfig *setting);

NM_AVAILABLE_IN_1_28
const char *const *nm_setting_ip_config_get_dhcp_reject_servers(NMSettingIPConfig *setting,
                                                                guint             *out_len);
NM_AVAILABLE_IN_1_28
void nm_setting_ip_config_add_dhcp_reject_server(NMSettingIPConfig *setting, const char *server);
NM_AVAILABLE_IN_1_28
void nm_setting_ip_config_remove_dhcp_reject_server(NMSettingIPConfig *setting, guint idx);
NM_AVAILABLE_IN_1_28
void nm_setting_ip_config_clear_dhcp_reject_servers(NMSettingIPConfig *setting);

G_END_DECLS

#endif /* NM_SETTING_IP_CONFIG_H */
