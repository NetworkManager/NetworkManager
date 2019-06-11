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

#include "nm-setting.h"

G_BEGIN_DECLS

/**
 * NMSettingProxyMethod:
 * @NM_SETTING_PROXY_METHOD_NONE: No Proxy for the Connection
 * @NM_SETTING_PROXY_METHOD_AUTO: DHCP obtained Proxy/ Manual override
 *
 * The Proxy method.
 *
 * Since: 1.6
 */
typedef enum {
	NM_SETTING_PROXY_METHOD_NONE = 0,
	NM_SETTING_PROXY_METHOD_AUTO = 1,
} NMSettingProxyMethod;

#define NM_TYPE_SETTING_PROXY            (nm_setting_proxy_get_type ())
#define NM_SETTING_PROXY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_PROXY, NMSettingProxy))
#define NM_SETTING_PROXY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_PROXY, NMSettingProxyClass))
#define NM_IS_SETTING_PROXY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_PROXY))
#define NM_IS_SETTING_PROXY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_PROXY))
#define NM_SETTING_PROXY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_PROXY, NMSettingProxyClass))

#define NM_SETTING_PROXY_SETTING_NAME "proxy"

#define NM_SETTING_PROXY_METHOD "method"
#define NM_SETTING_PROXY_BROWSER_ONLY "browser-only"
#define NM_SETTING_PROXY_PAC_URL "pac-url"
#define NM_SETTING_PROXY_PAC_SCRIPT "pac-script"

/**
 * NMSettingProxy:
 *
 * WWW Proxy Settings
 */
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
gboolean nm_setting_proxy_get_browser_only (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_pac_url (NMSettingProxy *setting);
NM_AVAILABLE_IN_1_6
const char *nm_setting_proxy_get_pac_script (NMSettingProxy *setting);

G_END_DECLS

#endif /* __NM_SETTING_PROXY_H__ */
