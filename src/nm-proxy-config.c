/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2016 Atul Anand <atulhjp@gmail.com>.
 */

#include "nm-default.h"

#include "nm-proxy-config.h"

#include <stdlib.h>

#include "nm-core-internal.h"

typedef struct {
	NMProxyConfigMethod method;
	char **proxies;
	char **excludes;
	gboolean browser_only;
	char *pac_url;
	char *pac_script;
} NMProxyConfigPrivate;

struct _NMProxyConfig {
	GObject parent;
	NMProxyConfigPrivate _priv;
};

struct _NMProxyConfigClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMProxyConfig, nm_proxy_config, G_TYPE_OBJECT)

#define NM_PROXY_CONFIG_GET_PRIVATE(self) \
	({ \
		/* preserve the const-ness of self. Unfortunately, that
		 * way, @self cannot be a void pointer */ \
		typeof (self) _self = (self); \
		\
		/* Get compiler error if variable is of wrong type */ \
		_nm_unused const NMProxyConfig *_self2 = (_self); \
		\
		nm_assert (NM_IS_PROXY_CONFIG (_self)); \
		&_self->_priv; \
	})

/*****************************************************************************/

static char **
_strdupv_nonempty (const char *const* strv)
{
	return (!strv || !strv[0]) ? NULL : g_strdupv ((char **) strv);
}

NMProxyConfig *
nm_proxy_config_new (void)
{
	return NM_PROXY_CONFIG (g_object_new (NM_TYPE_PROXY_CONFIG, NULL));
}

void
nm_proxy_config_set_method (NMProxyConfig *config, NMProxyConfigMethod method)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	priv->method = method;
}

NMProxyConfigMethod
nm_proxy_config_get_method (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->method;
}

void
nm_proxy_config_merge_setting (NMProxyConfig *config, NMSettingProxy *setting)
{
	const char *tmp = NULL;
	guint32 port = 0;
	NMProxyConfigPrivate *priv;
	NMSettingProxyMethod method;
	GPtrArray *proxies;

	if (!setting)
		return;

	g_return_if_fail (NM_IS_SETTING_PROXY (setting));

	priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_clear_pointer (&priv->proxies, g_strfreev);
	g_clear_pointer (&priv->excludes, g_strfreev);
	g_clear_pointer (&priv->pac_script, g_free);

	method = nm_setting_proxy_get_method (setting);
	switch (method) {
	case NM_SETTING_PROXY_METHOD_AUTO:
		priv->method = NM_PROXY_CONFIG_METHOD_AUTO;

		/* Free DHCP Obtained PAC Url (i.e Option 252)
		 * only when libnm overrides it.
		 */
		tmp = nm_setting_proxy_get_pac_url (setting);
		if (tmp) {
			g_free (priv->pac_url);
			priv->pac_url = g_strdup (tmp);
		}

		tmp = nm_setting_proxy_get_pac_script (setting);
		priv->pac_script = g_strdup (tmp);

		break;
	case NM_SETTING_PROXY_METHOD_MANUAL:
		priv->method = NM_PROXY_CONFIG_METHOD_MANUAL;

		priv->excludes = _strdupv_nonempty (nm_setting_proxy_get_no_proxy_for (setting));


		tmp = nm_setting_proxy_get_http_proxy (setting);
		port = nm_setting_proxy_get_http_port (setting);

		/* If HTTP Proxy has been selected for all Protocols
		 * set up a generic proxy in PacRunner i.e without a
		 * protocol prefix.
		 */
		proxies = g_ptr_array_new ();
		if (nm_setting_proxy_get_http_default (setting)) {
			if (tmp && port)
				g_ptr_array_add (proxies, g_strdup_printf ("%s:%u/", tmp, port));
		} else {
			if (tmp && port)
				g_ptr_array_add (proxies, g_strdup_printf ("http://%s:%u/", tmp, port));

			tmp = nm_setting_proxy_get_ssl_proxy (setting);
			port = nm_setting_proxy_get_ssl_port (setting);
			if (tmp && port)
				g_ptr_array_add (proxies, g_strdup_printf ("https://%s:%u/", tmp, port));

			tmp = nm_setting_proxy_get_ftp_proxy (setting);
			port = nm_setting_proxy_get_ftp_port (setting);
			if (tmp && port)
				g_ptr_array_add (proxies, g_strdup_printf ("ftp://%s:%u/", tmp, port));

			tmp = nm_setting_proxy_get_socks_proxy (setting);
			port = nm_setting_proxy_get_socks_port (setting);
			if (tmp && port) {
				g_ptr_array_add (proxies, g_strdup_printf (nm_setting_proxy_get_socks_version_5 (setting) ?
				                                           "socks5://%s:%u/" : "socks4://%s:%u/", tmp, port));
			}
		}

		priv->proxies = (char **) g_ptr_array_free (proxies, proxies->len == 0);
		break;
	case NM_SETTING_PROXY_METHOD_NONE:
		priv->method = NM_PROXY_CONFIG_METHOD_NONE;
		break;
	}

	priv->browser_only = nm_setting_proxy_get_browser_only (setting);
}

const char *const*
nm_proxy_config_get_proxies (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	/* don't return NULL */
	return priv->proxies ? ((const char *const*) priv->proxies) : ((const char *const*) &priv->proxies);
}

const char *const*
nm_proxy_config_get_excludes (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	/* don't return NULL */
	return priv->excludes ? ((const char *const*) priv->excludes) : ((const char *const*) &priv->excludes);
}

gboolean
nm_proxy_config_get_browser_only (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->browser_only;
}

void
nm_proxy_config_set_pac_url (NMProxyConfig *config, const char *url)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->pac_url);
	priv->pac_url = g_strdup (url);
}

const char *
nm_proxy_config_get_pac_url (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->pac_url;
}

void
nm_proxy_config_set_pac_script (NMProxyConfig *config, const char *script)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	g_free (priv->pac_script);
	priv->pac_script = g_strdup (script);
}

const char *
nm_proxy_config_get_pac_script (const NMProxyConfig *config)
{
	const NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	return priv->pac_script;
}

static void
nm_proxy_config_init (NMProxyConfig *config)
{
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (config);

	priv->method = NM_PROXY_CONFIG_METHOD_NONE;
}

static void
finalize (GObject *object)
{
	NMProxyConfig *self = NM_PROXY_CONFIG (object);
	NMProxyConfigPrivate *priv = NM_PROXY_CONFIG_GET_PRIVATE (self);

	g_strfreev (priv->proxies);
	g_strfreev (priv->excludes);
	g_free (priv->pac_url);
	g_free (priv->pac_script);

	G_OBJECT_CLASS (nm_proxy_config_parent_class)->finalize (object);
}

static void
nm_proxy_config_class_init (NMProxyConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = finalize;
}
