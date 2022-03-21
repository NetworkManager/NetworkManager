/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2016 Atul Anand <atulhjp@gmail.com>.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

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

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_METHOD, PROP_BROWSER_ONLY, PROP_PAC_URL, PROP_PAC_SCRIPT, );

typedef struct {
    char  *pac_url;
    char  *pac_script;
    gint32 method;
    bool   browser_only;
} NMSettingProxyPrivate;

/**
 * NMSettingProxy:
 *
 * WWW Proxy Settings
 */
struct _NMSettingProxy {
    NMSetting parent;
};

struct _NMSettingProxyClass {
    NMSettingClass parent;

    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingProxy, nm_setting_proxy, NM_TYPE_SETTING)

#define NM_SETTING_PROXY_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_PROXY, NMSettingProxyPrivate))

/*****************************************************************************/

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
nm_setting_proxy_get_method(NMSettingProxy *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PROXY(setting), NM_SETTING_PROXY_METHOD_NONE);

    return NM_SETTING_PROXY_GET_PRIVATE(setting)->method;
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
nm_setting_proxy_get_browser_only(NMSettingProxy *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PROXY(setting), FALSE);

    return NM_SETTING_PROXY_GET_PRIVATE(setting)->browser_only;
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
nm_setting_proxy_get_pac_url(NMSettingProxy *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PROXY(setting), NULL);

    return NM_SETTING_PROXY_GET_PRIVATE(setting)->pac_url;
}

/**
 * nm_setting_proxy_get_pac_script:
 * @setting: the #NMSettingProxy
 *
 * Returns: the PAC script.
 *
 * Since: 1.6
 **/
const char *
nm_setting_proxy_get_pac_script(NMSettingProxy *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PROXY(setting), NULL);

    return NM_SETTING_PROXY_GET_PRIVATE(setting)->pac_script;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingProxyPrivate *priv = NM_SETTING_PROXY_GET_PRIVATE(setting);

    if (!NM_IN_SET(priv->method, NM_SETTING_PROXY_METHOD_NONE, NM_SETTING_PROXY_METHOD_AUTO)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("invalid proxy method"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PROXY_SETTING_NAME, NM_SETTING_PROXY_PAC_URL);
        return FALSE;
    }

    if (priv->method != NM_SETTING_PROXY_METHOD_AUTO) {
        if (priv->pac_url) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("this property is not allowed for method none"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PROXY_SETTING_NAME,
                           NM_SETTING_PROXY_PAC_URL);
            return FALSE;
        }

        if (priv->pac_script) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("this property is not allowed for method none"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PROXY_SETTING_NAME,
                           NM_SETTING_PROXY_PAC_SCRIPT);
            return FALSE;
        }
    }

    if (priv->pac_script) {
        if (strlen(priv->pac_script) > 1 * 1024 * 1024) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("the script is too large"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PROXY_SETTING_NAME,
                           NM_SETTING_PROXY_PAC_SCRIPT);
            return FALSE;
        }
        if (!g_utf8_validate(priv->pac_script, -1, NULL)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("the script is not valid utf8"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PROXY_SETTING_NAME,
                           NM_SETTING_PROXY_PAC_SCRIPT);
            return FALSE;
        }
        if (!strstr(priv->pac_script, "FindProxyForURL")) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("the script lacks FindProxyForURL function"));
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_PROXY_SETTING_NAME,
                           NM_SETTING_PROXY_PAC_SCRIPT);
            return FALSE;
        }
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_proxy_init(NMSettingProxy *self)
{}

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
nm_setting_proxy_new(void)
{
    return g_object_new(NM_TYPE_SETTING_PROXY, NULL);
}

static void
nm_setting_proxy_class_init(NMSettingProxyClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingProxyPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

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
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_PROXY_METHOD,
                                             PROP_METHOD,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_PROXY_METHOD_NONE,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingProxyPrivate,
                                             method);

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
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_PROXY_BROWSER_ONLY,
                                               PROP_BROWSER_ONLY,
                                               FALSE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingProxyPrivate,
                                               browser_only);

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
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PROXY_PAC_URL,
                                              PROP_PAC_URL,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingProxyPrivate,
                                              pac_url);

    /**
     * NMSettingProxy:pac-script:
     *
     * PAC script for the connection. This is an UTF-8 encoded javascript code
     * that defines a FindProxyForURL() function.
     *
     * Since: 1.6
     **/
    /* ---nmcli---
     * property: pac-script
     * description: The PAC script. In the profile this must be an UTF-8 encoded javascript code that defines
     *   a FindProxyForURL() function.
     *   When setting the property in nmcli, a filename is accepted too. In that case,
     *   nmcli will read the content of the file and set the script. The prefixes "file://" and "js://" are
     *   supported to explicitly differentiate between the two.
     * ---end---
     */
    /* ---ifcfg-rh---
     * property: pac-script
     * variable: PAC_SCRIPT(+)
     * description: The PAC script. This is an UTF-8 encoded javascript code that defines a FindProxyForURL() function.
     * example: PAC_SCRIPT="function FindProxyForURL (url, host) { return 'PROXY proxy.example.com:8080; DIRECT'; }"
     * ---end---
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PROXY_PAC_SCRIPT,
                                              PROP_PAC_SCRIPT,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingProxyPrivate,
                                              pac_script);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_PROXY,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
