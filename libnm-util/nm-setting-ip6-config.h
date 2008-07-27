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
 * (C) Copyright 2007 - 2008 Red Hat, Inc.
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

#define NM_SETTING_IP6_CONFIG_METHOD            "method"
#define NM_SETTING_IP6_CONFIG_DNS               "dns"
#define NM_SETTING_IP6_CONFIG_DNS_SEARCH        "dns-search"
#define NM_SETTING_IP6_CONFIG_ADDRESSES         "addresses"
#define NM_SETTING_IP6_CONFIG_ROUTES            "routes"
#define NM_SETTING_IP6_CONFIG_IGNORE_DHCPV6_DNS "ignore-dhcpv6-dns"
#define NM_SETTING_IP6_CONFIG_DISABLE_RA        "disable-ra"
#define NM_SETTING_IP6_CONFIG_DHCPV6_MODE       "dhcpv6-mode"

#define NM_SETTING_IP6_CONFIG_METHOD_AUTO   "auto"
#define NM_SETTING_IP6_CONFIG_METHOD_MANUAL "manual"
#define NM_SETTING_IP6_CONFIG_METHOD_SHARED "shared"

#define NM_SETTING_IP6_CONFIG_DHCPV6_MODE_INFO    "info"
#define NM_SETTING_IP6_CONFIG_DHCPV6_MODE_REQUEST "request"

typedef struct {
	struct in6_addr address;
	guint32 prefix;
	struct in6_addr gateway;
} NMSettingIP6Address;

typedef struct {
	NMSetting parent;

	char *method;
	GSList *dns;        /* array of struct in6_addr */
	GSList *dns_search; /* list of strings */
	GSList *addresses;  /* array of NMSettingIP6Address */
	GSList *routes;     /* array of NMSettingIP6Address */
	gboolean ignore_dhcpv6_dns;
	gboolean disable_ra;
	char *dhcpv6_mode;
} NMSettingIP6Config;

typedef struct {
	NMSettingClass parent;
} NMSettingIP6ConfigClass;

GType nm_setting_ip6_config_get_type (void);

NMSetting *nm_setting_ip6_config_new (void);

G_END_DECLS

#endif /* NM_SETTING_IP6_CONFIG_H */
