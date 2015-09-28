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

#ifndef __NM_SETTING_IP4_CONFIG_H__
#define __NM_SETTING_IP4_CONFIG_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting-ip-config.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_IP4_CONFIG            (nm_setting_ip4_config_get_type ())
#define NM_SETTING_IP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4Config))
#define NM_SETTING_IP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_IP4CONFIG, NMSettingIP4ConfigClass))
#define NM_IS_SETTING_IP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_IS_SETTING_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_IP4_CONFIG))
#define NM_SETTING_IP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_IP4_CONFIG, NMSettingIP4ConfigClass))

#define NM_SETTING_IP4_CONFIG_SETTING_NAME "ipv4"

#define NM_SETTING_IP4_CONFIG_DHCP_CLIENT_ID     "dhcp-client-id"

#define NM_SETTING_IP4_CONFIG_DHCP_TIMEOUT       "dhcp-timeout"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_AUTO:
 *
 * IPv4 configuration should be automatically determined via a method appropriate
 * for the hardware interface, ie DHCP or PPP or some other device-specific
 * manner.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_AUTO       "auto"

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
#define NM_SETTING_IP4_CONFIG_METHOD_MANUAL     "manual"

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
#define NM_SETTING_IP4_CONFIG_METHOD_SHARED     "shared"

/**
 * NM_SETTING_IP4_CONFIG_METHOD_DISABLED:
 *
 * This connection does not use or require IPv4 address and it should be disabled.
 */
#define NM_SETTING_IP4_CONFIG_METHOD_DISABLED   "disabled"

struct _NMSettingIP4Config {
	NMSettingIPConfig parent;
};

typedef struct {
	NMSettingIPConfigClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingIP4ConfigClass;

GType nm_setting_ip4_config_get_type (void);

NMSetting *nm_setting_ip4_config_new (void);

const char *nm_setting_ip4_config_get_dhcp_client_id     (NMSettingIP4Config *setting);
NM_AVAILABLE_IN_1_2
int nm_setting_ip4_config_get_dhcp_timeout               (NMSettingIP4Config *setting);

G_END_DECLS

#endif /* __NM_SETTING_IP4_CONFIG_H__ */
