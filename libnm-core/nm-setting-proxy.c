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

#include "nm-default.h"

#include "nm-setting-proxy.h"
#include "nm-utils.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-proxy
 * @short_description: Describes proxy URL, script and other related properties
 *
 * The #NMSettingProxy object is a #NMSetting subclass that describes properties
 * related to Proxy settings like PAC URL, PAC script etc.
 *
 * NetworkManager support 2 values for the #NMSettingProxy:method property for
 * proxy. If "auto" is specified then WPAD takes place and the appropriate details
 * are pushed into PacRunner or user can override this URL with a new PAC URL or a
 * PAC script. If "none" is selected then no proxy configuration is given to PacRunner
 * to fulfill client queries.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingProxy, nm_setting_proxy, NM_TYPE_SETTING,
                         _nm_register_setting (PROXY, NM_SETTING_PRIORITY_IP))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_PROXY)

#define NM_SETTING_PROXY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_PROXY, NMSettingProxyPrivate))

typedef struct {
	NMSettingProxyMethod method;
	gboolean browser_only;
	char *pac_url;
	char *pac_script;
} NMSettingProxyPrivate;

enum {
	PROP_0,
	PROP_METHOD,
	PROP_BROWSER_ONLY,
	PROP_PAC_URL,
	PROP_PAC_SCRIPT,

	LAST_PROP
};

/**
 * nm_setting_proxy_new:
 *
 * Creates a new #NMSettingProxy object.
 *
 * Returns: the new empty #NMSettingProxy object
 *
 * Since: 1.6
 **/
NMSetting *
nm_setting_proxy_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_PROXY, NULL);
}

/**
 * nm_setting_proxy_get_method:
 * @setting: the #NMSettingProxy
 *
 * Returns the proxy configuration method. By default the value is %NM_SETTING_PROXY_METHOD_NONE.
 * %NM_SETTING_PROXY_METHOD_NONE should be selected for a connection intended for direct network
 * access.
 *
 * Returns: the proxy configuration method
 *
 * Since: 1.6
 **/
NMSettingProxyMethod
nm_setting_proxy_get_method (NMSettingProxy *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PROXY (setting), NM_SETTING_PROXY_METHOD_NONE);

	return NM_SETTING_PROXY_GET_PRIVATE (setting)->method;
}

/**
 * nm_setting_proxy_get_browser_only:
 * @setting: the #NMSettingProxy
 *
 * Returns: %TRUE if this proxy configuration is only for browser
 * clients/schemes, %FALSE otherwise.
 *
 * Since: 1.6
 **/
gboolean
nm_setting_proxy_get_browser_only (NMSettingProxy *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PROXY (setting), FALSE);

	return NM_SETTING_PROXY_GET_PRIVATE (setting)->browser_only;
}

/**
 * nm_setting_proxy_get_pac_url:
 * @setting: the #NMSettingProxy
 *
 * Returns: the PAC URL for obtaining PAC file
 *
 * Since: 1.6
 **/
const char *
nm_setting_proxy_get_pac_url (NMSettingProxy *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PROXY (setting), NULL);

	return NM_SETTING_PROXY_GET_PRIVATE (setting)->pac_url;
}

/**
 * nm_setting_proxy_get_pac_script:
 * @setting: the #NMSettingProxy
 *
 * Returns: the PAC script
 *
 * Since: 1.6
 **/
const char *
nm_setting_proxy_get_pac_script (NMSettingProxy *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PROXY (setting), NULL);

	return NM_SETTING_PROXY_GET_PRIVATE (setting)->pac_script;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingProxyPrivate *priv = NM_SETTING_PROXY_GET_PRIVATE (setting);
	NMSettingProxyMethod method;

	method = priv->method;

	if (!NM_IN_SET (method,
	                NM_SETTING_PROXY_METHOD_NONE,
	                NM_SETTING_PROXY_METHOD_AUTO)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("invalid proxy method"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_URL);
		return FALSE;
	}

	if (method != NM_SETTING_PROXY_METHOD_AUTO) {
		if (priv->pac_url) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for method none"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_URL);
			return FALSE;
		}

		if (priv->pac_script) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("this property is not allowed for method none"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_SCRIPT);
			return FALSE;
		}
	}

	if (priv->pac_script) {
		if (strlen (priv->pac_script) > 1*1024*1024) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("the script is too large"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_SCRIPT);
			return FALSE;
		}
		if (!g_utf8_validate (priv->pac_script, -1, NULL)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("the script is not valid utf8"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_SCRIPT);
			return FALSE;
		}
		if (!strstr (priv->pac_script, "FindProxyForURL")) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("the script lacks FindProxyForURL function"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_SCRIPT);
			return FALSE;
		}
	}

	return TRUE;
}

static void
nm_setting_proxy_init (NMSettingProxy *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingProxy *self = NM_SETTING_PROXY (object);
	NMSettingProxyPrivate *priv = NM_SETTING_PROXY_GET_PRIVATE (self);

	g_free (priv->pac_url);
	g_free (priv->pac_script);

	G_OBJECT_CLASS (nm_setting_proxy_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingProxy *setting = NM_SETTING_PROXY (object);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_int (value, nm_setting_proxy_get_method (setting));
		break;
	case PROP_BROWSER_ONLY:
		g_value_set_boolean (value, nm_setting_proxy_get_browser_only (setting));
		break;
	case PROP_PAC_URL:
		g_value_set_string (value, nm_setting_proxy_get_pac_url (setting));
		break;
	case PROP_PAC_SCRIPT:
		g_value_set_string (value, nm_setting_proxy_get_pac_script (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingProxyPrivate *priv = NM_SETTING_PROXY_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_METHOD:
		priv->method = g_value_get_int (value);
		break;
	case PROP_BROWSER_ONLY:
		priv->browser_only = g_value_get_boolean (value);
		break;
	case PROP_PAC_URL:
		g_free (priv->pac_url);
		priv->pac_url = g_value_dup_string (value);
		break;
	case PROP_PAC_SCRIPT:
		g_free (priv->pac_script);
		priv->pac_script = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_proxy_class_init (NMSettingProxyClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingProxyPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify = verify;

	/**
	 * NMSettingProxy:method:
	 *
	 * Method for proxy configuration, Default is %NM_SETTING_PROXY_METHOD_NONE
	 *
	 * Since: 1.6
	 **/
	/* ---ifcfg-rh---
	 * property: method
	 * variable: PROXY_METHOD(+)
	 * default: none
	 * description: Method for proxy configuration. For "auto", WPAD is used for
	 *   proxy configuration, or set the PAC file via PAC_URL or PAC_SCRIPT.
	 * values: none, auto
	 * ---end---
	 */
	g_object_class_install_property
	    (object_class, PROP_METHOD,
	     g_param_spec_int (NM_SETTING_PROXY_METHOD, "", "",
	                       G_MININT32, G_MAXINT32, NM_SETTING_PROXY_METHOD_NONE,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingProxy:browser-only:
	 *
	 * Whether the proxy configuration is for browser only.
	 *
	 * Since: 1.6
	 **/
	/* ---ifcfg-rh---
	 * property: browser-only
	 * variable: BROWSER_ONLY(+)
	 * default: no
	 * description: Whether the proxy configuration is for browser only.
	 * ---end---
	 */
	g_object_class_install_property
	    (object_class, PROP_BROWSER_ONLY,
	     g_param_spec_boolean (NM_SETTING_PROXY_BROWSER_ONLY, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingProxy:pac-url:
	 *
	 * PAC URL for obtaining PAC file.
	 *
	 * Since: 1.6
	 **/
	/* ---ifcfg-rh---
	 * property: pac-url
	 * variable: PAC_URL(+)
	 * description: URL for PAC file.
	 * example: PAC_URL=http://wpad.mycompany.com/wpad.dat
	 * ---end---
	 */
	g_object_class_install_property
	    (object_class, PROP_PAC_URL,
	     g_param_spec_string (NM_SETTING_PROXY_PAC_URL, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingProxy:pac-script:
	 *
	 * PAC script for the connection.
	 *
	 * Since: 1.6
	 **/
	/* ---ifcfg-rh---
	 * property: pac-script
	 * variable: PAC_SCRIPT(+)
	 * description: Path of the PAC script.
	 * example: PAC_SCRIPT=/home/joe/proxy.pac
	 * ---end---
	 */
	g_object_class_install_property
	    (object_class, PROP_PAC_SCRIPT,
	     g_param_spec_string (NM_SETTING_PROXY_PAC_SCRIPT, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS));
}
