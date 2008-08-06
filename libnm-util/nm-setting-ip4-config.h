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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
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
#define NM_SETTING_IP4_CONFIG_DHCP_HOSTNAME      "dhcp-hostname"

#define NM_SETTING_IP4_CONFIG_METHOD_AUTO       "auto"
#define NM_SETTING_IP4_CONFIG_METHOD_LINK_LOCAL "link-local"
#define NM_SETTING_IP4_CONFIG_METHOD_MANUAL     "manual"
#define NM_SETTING_IP4_CONFIG_METHOD_SHARED     "shared"

typedef struct {
	guint32 address;   /* network byte order */
	guint32 prefix;
	guint32 gateway;   /* network byte order */
} NMSettingIP4Address;

typedef struct {
	guint32 address;   /* network byte order */
	guint32 prefix;
	guint32 next_hop;   /* network byte order */
	guint32 metric;    /* lower metric == more preferred */
} NMSettingIP4Route;

typedef struct {
	NMSetting parent;

	char *method;
	GArray *dns;        /* array of guint32; elements in network byte order */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMSettingIP4Address */
	GSList *routes;     /* array of NMSettingIP4Route */
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_client_id;
	char *dhcp_hostname;
} NMSettingIP4Config;

typedef struct {
	NMSettingClass parent;
} NMSettingIP4ConfigClass;

GType nm_setting_ip4_config_get_type (void);

NMSetting *nm_setting_ip4_config_new (void);

G_END_DECLS

#endif /* NM_SETTING_IP4_CONFIG_H */
