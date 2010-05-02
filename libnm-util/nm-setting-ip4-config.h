/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_IP4_CONFIG_H
#define NM_SETTING_IP4_CONFIG_H

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP4_CONFIG            (nm_setting_ip4_config_get_type ())
#define NM_SETTING_IP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4Config))
#define NM_SETTING_IP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IP4CONFIG, NMSettingIP4ConfigClass))
#define NM_IS_SETTING_IP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_IS_SETTING_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_SETTING_IP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigClass))

#define NM_SETTING_IP4_CONFIG_SETTING_NAME "ipv4"

typedef enum
{
	NM_SETTING_IP4_CONFIG_ERROR_UNKNOWN = 0,
	NM_SETTING_IP4_CONFIG_ERROR_INVALID_PROPERTY,
	NM_SETTING_IP4_CONFIG_ERROR_MISSING_PROPERTY,
	NM_SETTING_IP4_CONFIG_ERROR_NOT_ALLOWED_FOR_METHOD
} NMSettingIP4ConfigError;

#define NM_TYPE_SETTING_IP4_CONFIG_ERROR (nm_setting_ip4_config_error_get_type ()) 
GType nm_setting_ip4_config_error_get_type (void);

#define NM_SETTING_IP4_CONFIG_ERROR nm_setting_ip4_config_error_quark ()
GQuark nm_setting_ip4_config_error_quark (void);

#define NM_SETTING_IP4_CONFIG_METHOD             "method"
#define NM_SETTING_IP4_CONFIG_DNS                "dns"
#define NM_SETTING_IP4_CONFIG_DNS_SEARCH         "dns-search"
#define NM_SETTING_IP4_CONFIG_ADDRESSES          "addresses"
#define NM_SETTING_IP4_CONFIG_ROUTES             "routes"
#define NM_SETTING_IP4_CONFIG_IGNORE_AUTO_ROUTES "ignore-auto-routes"
#define NM_SETTING_IP4_CONFIG_IGNORE_AUTO_DNS    "ignore-auto-dns"
#define NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID     "dhcp-client-id"
#define NM_SETTING_IP4_CONFIG_DHCP_SEND_HOSTNAME "dhcp-send-hostname"
#define NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME      "dhcp-hostname"
#define NM_SETTING_IP4_CONFIG_NEVER_DEFAULT      "never-default"
#define NM_SETTING_IP4_CONFIG_MAY_FAIL           "may-fail"

#define NM_SETTING_IP4_CONFIG_METHOD_AUTO       "auto"
#define NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL "link-local"
#define NM_SETTING_IP4_CONFIG_METHOD_MANUAL     "manual"
#define NM_SETTING_IP4_CONFIG_METHOD_SHARED     "shared"
#define NM_SETTING_IP4_CONFIG_METHOD_DISABLED   "disabled"

typedef struct NMIP4Address NMIP4Address;

NMIP4Address * nm_ip4_address_new         (void);
NMIP4Address * nm_ip4_address_dup         (NMIP4Address *source);
void           nm_ip4_address_ref         (NMIP4Address *address);
void           nm_ip4_address_unref       (NMIP4Address *address);
/* Return TRUE if addresses are identical */
gboolean       nm_ip4_address_compare     (NMIP4Address *address, NMIP4Address *other);

guint32        nm_ip4_address_get_address (NMIP4Address *address);
void           nm_ip4_address_set_address (NMIP4Address *address,
                                           guint32 addr);  /* network byte order */

guint32        nm_ip4_address_get_prefix  (NMIP4Address *address);
void           nm_ip4_address_set_prefix  (NMIP4Address *address,
                                           guint32 prefix);

guint32        nm_ip4_address_get_gateway (NMIP4Address *address);
void           nm_ip4_address_set_gateway (NMIP4Address *address,
                                           guint32 gateway);  /* network byte order */

typedef struct NMIP4Route NMIP4Route;

NMIP4Route * nm_ip4_route_new          (void);
NMIP4Route * nm_ip4_route_dup          (NMIP4Route *route);
void         nm_ip4_route_ref          (NMIP4Route *route);
void         nm_ip4_route_unref        (NMIP4Route *route);
/* Return TRUE if routes are identical */
gboolean     nm_ip4_route_compare      (NMIP4Route *route, NMIP4Route *other);

guint32      nm_ip4_route_get_dest     (NMIP4Route *route);
void         nm_ip4_route_set_dest     (NMIP4Route *route,
                                        guint32 dest);  /* network byte order */

guint32      nm_ip4_route_get_prefix   (NMIP4Route *route);
void         nm_ip4_route_set_prefix   (NMIP4Route *route,
                                        guint32 prefix);

guint32      nm_ip4_route_get_next_hop (NMIP4Route *route);
void         nm_ip4_route_set_next_hop (NMIP4Route *route,
                                        guint32 next_hop);  /* network byte order */

guint32      nm_ip4_route_get_metric   (NMIP4Route *route);
void         nm_ip4_route_set_metric   (NMIP4Route *route,
                                        guint32 metric);


typedef struct {
	NMSetting parent;
} NMSettingIP4Config;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingIP4ConfigClass;

GType nm_setting_ip4_config_get_type (void);

NMSetting *   nm_setting_ip4_config_new                    (void);
const char *  nm_setting_ip4_config_get_method             (NMSettingIP4Config *setting);

guint32       nm_setting_ip4_config_get_num_dns            (NMSettingIP4Config *setting);
guint32       nm_setting_ip4_config_get_dns                (NMSettingIP4Config *setting, guint32 i);
gboolean      nm_setting_ip4_config_add_dns                (NMSettingIP4Config *setting, guint32 dns);
void          nm_setting_ip4_config_remove_dns             (NMSettingIP4Config *setting, guint32 i);
void          nm_setting_ip4_config_clear_dns              (NMSettingIP4Config *setting);

guint32       nm_setting_ip4_config_get_num_dns_searches   (NMSettingIP4Config *setting);
const char *  nm_setting_ip4_config_get_dns_search         (NMSettingIP4Config *setting, guint32 i);
gboolean      nm_setting_ip4_config_add_dns_search         (NMSettingIP4Config *setting, const char *dns_search);
void          nm_setting_ip4_config_remove_dns_search      (NMSettingIP4Config *setting, guint32 i);
void          nm_setting_ip4_config_clear_dns_searches     (NMSettingIP4Config *setting);

guint32       nm_setting_ip4_config_get_num_addresses      (NMSettingIP4Config *setting);
NMIP4Address *nm_setting_ip4_config_get_address            (NMSettingIP4Config *setting, guint32 i);
gboolean      nm_setting_ip4_config_add_address            (NMSettingIP4Config *setting, NMIP4Address *address);
void          nm_setting_ip4_config_remove_address         (NMSettingIP4Config *setting, guint32 i);
void          nm_setting_ip4_config_clear_addresses        (NMSettingIP4Config *setting);

guint32       nm_setting_ip4_config_get_num_routes         (NMSettingIP4Config *setting);
NMIP4Route *  nm_setting_ip4_config_get_route              (NMSettingIP4Config *setting, guint32 i);
gboolean      nm_setting_ip4_config_add_route              (NMSettingIP4Config *setting, NMIP4Route *route);
void          nm_setting_ip4_config_remove_route           (NMSettingIP4Config *setting, guint32 i);
void          nm_setting_ip4_config_clear_routes           (NMSettingIP4Config *setting);

gboolean      nm_setting_ip4_config_get_ignore_auto_routes (NMSettingIP4Config *setting);
gboolean      nm_setting_ip4_config_get_ignore_auto_dns    (NMSettingIP4Config *setting);
const char *  nm_setting_ip4_config_get_dhcp_client_id     (NMSettingIP4Config *setting);
gboolean      nm_setting_ip4_config_get_dhcp_send_hostname (NMSettingIP4Config *setting);
const char *  nm_setting_ip4_config_get_dhcp_hostname      (NMSettingIP4Config *setting);

gboolean      nm_setting_ip4_config_get_never_default      (NMSettingIP4Config *setting);

gboolean      nm_setting_ip4_config_get_may_fail           (NMSettingIP4Config *setting);

G_END_DECLS

#endif /* NM_SETTING_IP4_CONFIG_H */
