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
 * (C) Copyright 2016 Atul Anand <atulhjp@gmail.com>.
 */

#ifndef __NM_SETTING_PROXY_H__
#define __NM_SETTING_PROXY_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

/**
 * NMSettingProxyMethod:
 * @NM_SETTING_PROXY_METHOD_AUTO:   DHCP obtained Proxy
 * @NM_SETTING_PROXY_METHOD_MANUAL: Manual mode
 * @NM_SETTING_PROXY_METHOD_NONE:   No Proxy for the Connection
 *
 * The Proxy method.
 *
 * Since: 1.6
 */
typedef enum {
	NM_SETTING_PROXY_METHOD_AUTO = 0,
	NM_SETTING_PROXY_METHOD_MANUAL,
	NM_SETTING_PROXY_METHOD_NONE
} NMSettingProxyMethod;

#define NM_TYPE_SETTING_PROXY            (nm_setting_proxy_get_type ())
#define NM_SETTING_PROXY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PROXY, NMSettingProxy))
#define NM_SETTING_PROXY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PROXY, NMSettingProxyClass))
#define NM_IS_SETTING_PROXY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PROXY))
#define NM_IS_SETTING_PROXY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_PROXY))
#define NM_SETTING_PROXY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PROXY, NMSettingProxyClass))

#define NM_SETTING_PROXY_SETTING_NAME "proxy"

#define NM_SETTING_PROXY_METHOD "method"
#define NM_SETTING_PROXY_HTTP_PROXY "http-proxy"
#define NM_SETTING_PROXY_HTTP_PORT "http-port"
#define NM_SETTING_PROXY_HTTP_DEFAULT "http-default"
#define NM_SETTING_PROXY_SSL_PROXY "ssl-proxy"
#define NM_SETTING_PROXY_SSL_PORT "ssl-port"
#define NM_SETTING_PROXY_FTP_PROXY "ftp-proxy"
#define NM_SETTING_PROXY_FTP_PORT "ftp-port"
#define NM_SETTING_PROXY_SOCKS_PROXY "socks-proxy"
#define NM_SETTING_PROXY_SOCKS_PORT "socks-port"
#define NM_SETTING_PROXY_SOCKS_VERSION_5 "socks-version-5"
#define NM_SETTING_PROXY_NO_PROXY_FOR "no-proxy-for"
#define NM_SETTING_PROXY_BROWSER_ONLY "browser-only"
#define NM_SETTING_PROXY_PAC_URL "pac-url"
#define NM_SETTING_PROXY_PAC_SCRIPT "pac-script"

struct _NMSettingProxy {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	gpointer padding[4];
} NMSettingProxyClass;

NM_AVAILABLE_IN_1_6
GType nm_setting_proxy_get_type (void);

NM_AVAILABLE_IN_1_6
NMSetting *nm_setting_proxy_new (void);

NM_AVAILABLE_IN_1_6
NMSettingProxyMethod nm_setting_proxy_get_method (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_http_proxy (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
guint32 nm_setting_proxy_get_http_port (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
gboolean nm_setting_proxy_get_http_default (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_ssl_proxy (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
guint32 nm_setting_proxy_get_ssl_port (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_ftp_proxy (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
guint32 nm_setting_proxy_get_ftp_port (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_socks_proxy (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
guint32 nm_setting_proxy_get_socks_port (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
gboolean nm_setting_proxy_get_socks_version_5 (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *const*nm_setting_proxy_get_no_proxy_for (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
gboolean nm_setting_proxy_get_browser_only (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_pac_url (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_pac_script (NMSettingProxy *setting);

G_END_DECLS

#endif /* __NM_SETTING_PROXY_H__ */
