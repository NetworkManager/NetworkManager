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
    char *               parent;
    char *               service;
    char *               username;
    char *               password;
    NMSettingSecretFlags password_flags;
} NMSettingPppoePrivate;

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
    NMSettingPppoePrivate *priv       = NM_SETTING_PPPOE_GET_PRIVATE(setting);
    gs_free_error GError *local_error = NULL;

    if (!priv->username) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_USERNAME);
        return FALSE;
    } else if (!strlen(priv->username)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_USERNAME);
        return FALSE;
    }

    if (priv->service && !strlen(priv->service)) {
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
need_secrets(NMSetting *setting)
{
    NMSettingPppoePrivate *priv    = NM_SETTING_PPPOE_GET_PRIVATE(setting);
    GPtrArray *            secrets = NULL;

    if (priv->password)
        return NULL;

    if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        secrets = g_ptr_array_sized_new(1);
        g_ptr_array_add(secrets, NM_SETTING_PPPOE_PASSWORD);
    }

    return secrets;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingPppoe *setting = NM_SETTING_PPPOE(object);

    switch (prop_id) {
    case PROP_PARENT:
        g_value_set_string(value, nm_setting_pppoe_get_parent(setting));
        break;
    case PROP_SERVICE:
        g_value_set_string(value, nm_setting_pppoe_get_service(setting));
        break;
    case PROP_USERNAME:
        g_value_set_string(value, nm_setting_pppoe_get_username(setting));
        break;
    case PROP_PASSWORD:
        g_value_set_string(value, nm_setting_pppoe_get_password(setting));
        break;
    case PROP_PASSWORD_FLAGS:
        g_value_set_flags(value, nm_setting_pppoe_get_password_flags(setting));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingPppoePrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_PARENT:
        g_free(priv->parent);
        priv->parent = g_value_dup_string(value);
        break;
    case PROP_SERVICE:
        g_free(priv->service);
        priv->service = g_value_dup_string(value);
        break;
    case PROP_USERNAME:
        g_free(priv->username);
        priv->username = g_value_dup_string(value);
        break;
    case PROP_PASSWORD:
        g_free(priv->password);
        priv->password = g_value_dup_string(value);
        break;
    case PROP_PASSWORD_FLAGS:
        priv->password_flags = g_value_get_flags(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
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
finalize(GObject *object)
{
    NMSettingPppoePrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE(object);

    g_free(priv->parent);
    g_free(priv->username);
    g_free(priv->password);
    g_free(priv->service);

    G_OBJECT_CLASS(nm_setting_pppoe_parent_class)->finalize(object);
}

static void
nm_setting_pppoe_class_init(NMSettingPppoeClass *klass)
{
    GObjectClass *  object_class  = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class = NM_SETTING_CLASS(klass);

    g_type_class_add_private(klass, sizeof(NMSettingPppoePrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

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
    obj_properties[PROP_PARENT] = g_param_spec_string(
        NM_SETTING_PPPOE_PARENT,
        "",
        "",
        NULL,
        G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingPppoe:service:
     *
     * If specified, instruct PPPoE to only initiate sessions with access
     * concentrators that provide the specified service.  For most providers,
     * this should be left blank.  It is only required if there are multiple
     * access concentrators or a specific service is known to be required.
     **/
    obj_properties[PROP_SERVICE] = g_param_spec_string(NM_SETTING_PPPOE_SERVICE,
                                                       "",
                                                       "",
                                                       NULL,
                                                       G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingPppoe:username:
     *
     * Username used to authenticate with the PPPoE service.
     **/
    obj_properties[PROP_USERNAME] = g_param_spec_string(NM_SETTING_PPPOE_USERNAME,
                                                        "",
                                                        "",
                                                        NULL,
                                                        G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingPppoe:password:
     *
     * Password used to authenticate with the PPPoE service.
     **/
    obj_properties[PROP_PASSWORD] =
        g_param_spec_string(NM_SETTING_PPPOE_PASSWORD,
                            "",
                            "",
                            NULL,
                            G_PARAM_READWRITE | NM_SETTING_PARAM_SECRET | G_PARAM_STATIC_STRINGS);

    /**
     * NMSettingPppoe:password-flags:
     *
     * Flags indicating how to handle the #NMSettingPppoe:password property.
     **/
    obj_properties[PROP_PASSWORD_FLAGS] =
        g_param_spec_flags(NM_SETTING_PPPOE_PASSWORD_FLAGS,
                           "",
                           "",
                           NM_TYPE_SETTING_SECRET_FLAGS,
                           NM_SETTING_SECRET_FLAG_NONE,
                           G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class, NM_META_SETTING_TYPE_PPPOE);
}
