/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-pppoe.h"

#include "nm-setting-ppp.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-pppoe
 * @short_description: Describes PPPoE connection properties
 *
 * The #NMSettingPppoe object is a #NMSetting subclass that describes
 * properties necessary for connection to networks that require PPPoE connections
 * to provide IP transport, for example cable or DSL modems.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT,
                                  PROP_SERVICE,
                                  PROP_USERNAME,
                                  PROP_PASSWORD,
                                  PROP_PASSWORD_FLAGS, );

typedef struct {
    char *parent;
    char *service;
    char *username;
    char *password;
    guint password_flags;
} NMSettingPppoePrivate;

/**
 * NMSettingPppoe:
 *
 * PPP-over-Ethernet Settings
 */
struct _NMSettingPppoe {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingPppoeClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingPppoe, nm_setting_pppoe, NM_TYPE_SETTING)

#define NM_SETTING_PPPOE_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_PPPOE, NMSettingPppoePrivate))

/*****************************************************************************/

/**
 * nm_setting_pppoe_get_parent:
 * @setting: the #NMSettingPppoe
 *
 * Returns: the #NMSettingPppoe:parent property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_pppoe_get_parent(NMSettingPppoe *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPPOE(setting), NULL);

    return NM_SETTING_PPPOE_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_pppoe_get_service:
 * @setting: the #NMSettingPppoe
 *
 * Returns: the #NMSettingPppoe:service property of the setting
 **/
const char *
nm_setting_pppoe_get_service(NMSettingPppoe *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPPOE(setting), NULL);

    return NM_SETTING_PPPOE_GET_PRIVATE(setting)->service;
}

/**
 * nm_setting_pppoe_get_username:
 * @setting: the #NMSettingPppoe
 *
 * Returns: the #NMSettingPppoe:username property of the setting
 **/
const char *
nm_setting_pppoe_get_username(NMSettingPppoe *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPPOE(setting), NULL);

    return NM_SETTING_PPPOE_GET_PRIVATE(setting)->username;
}

/**
 * nm_setting_pppoe_get_password:
 * @setting: the #NMSettingPppoe
 *
 * Returns: the #NMSettingPppoe:password property of the setting
 **/
const char *
nm_setting_pppoe_get_password(NMSettingPppoe *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPPOE(setting), NULL);

    return NM_SETTING_PPPOE_GET_PRIVATE(setting)->password;
}

/**
 * nm_setting_pppoe_get_password_flags:
 * @setting: the #NMSettingPppoe
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingPppoe:password
 **/
NMSettingSecretFlags
nm_setting_pppoe_get_password_flags(NMSettingPppoe *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_PPPOE(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_PPPOE_GET_PRIVATE(setting)->password_flags;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingPppoePrivate *priv        = NM_SETTING_PPPOE_GET_PRIVATE(setting);
    gs_free_error GError  *local_error = NULL;

    if (nm_str_is_empty(priv->username)) {
        if (!priv->username) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_MISSING_PROPERTY,
                                _("property is missing"));
        } else {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("property is empty"));
        }
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_USERNAME);
        return FALSE;
    }

    if (priv->service && nm_str_is_empty(priv->service)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_SERVICE);
        return FALSE;
    }

    if (priv->parent && !nm_utils_ifname_valid_kernel(priv->parent, &local_error)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "'%s': %s",
                    priv->parent,
                    local_error->message);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_PARENT);
        return FALSE;
    }

    return TRUE;
}

static GPtrArray *
need_secrets(NMSetting *setting, gboolean check_rerequest)
{
    NMSettingPppoePrivate *priv    = NM_SETTING_PPPOE_GET_PRIVATE(setting);
    GPtrArray             *secrets = NULL;

    if (!check_rerequest && priv->password)
        return NULL;

    if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        secrets = g_ptr_array_sized_new(1);
        g_ptr_array_add(secrets, NM_SETTING_PPPOE_PASSWORD);
    }

    return secrets;
}

/*****************************************************************************/

static void
nm_setting_pppoe_init(NMSettingPppoe *setting)
{}

/**
 * nm_setting_pppoe_new:
 *
 * Creates a new #NMSettingPppoe object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingPppoe object
 **/
NMSetting *
nm_setting_pppoe_new(void)
{
    return g_object_new(NM_TYPE_SETTING_PPPOE, NULL);
}

static void
nm_setting_pppoe_class_init(NMSettingPppoeClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingPppoePrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify       = verify;
    setting_class->need_secrets = need_secrets;

    /**
     * NMSettingPppoe:parent:
     *
     * If given, specifies the parent interface name on which this PPPoE
     * connection should be created.  If this property is not specified,
     * the connection is activated on the interface specified in
     * #NMSettingConnection:interface-name of #NMSettingConnection.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPPOE_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingPppoePrivate,
                                              parent);

    /**
     * NMSettingPppoe:service:
     *
     * If specified, instruct PPPoE to only initiate sessions with access
     * concentrators that provide the specified service.  For most providers,
     * this should be left blank.  It is only required if there are multiple
     * access concentrators or a specific service is known to be required.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPPOE_SERVICE,
                                              PROP_SERVICE,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingPppoePrivate,
                                              service);

    /**
     * NMSettingPppoe:username:
     *
     * Username used to authenticate with the PPPoE service.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPPOE_USERNAME,
                                              PROP_USERNAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingPppoePrivate,
                                              username);

    /**
     * NMSettingPppoe:password:
     *
     * Password used to authenticate with the PPPoE service.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_PPPOE_PASSWORD,
                                              PROP_PASSWORD,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingPppoePrivate,
                                              password);

    /**
     * NMSettingPppoe:password-flags:
     *
     * Flags indicating how to handle the #NMSettingPppoe:password property.
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_PPPOE_PASSWORD_FLAGS,
                                                    PROP_PASSWORD_FLAGS,
                                                    NMSettingPppoePrivate,
                                                    password_flags);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_PPPOE,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
