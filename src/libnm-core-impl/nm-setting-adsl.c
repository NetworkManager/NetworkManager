/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2013 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-adsl.h"

#include "nm-setting-ppp.h"
#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-adsl
 * @short_description: Describes ADSL-based properties
 *
 * The #NMSettingAdsl object is a #NMSetting subclass that describes
 * properties of ADSL connections.
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_USERNAME,
                                  PROP_PASSWORD,
                                  PROP_PASSWORD_FLAGS,
                                  PROP_PROTOCOL,
                                  PROP_ENCAPSULATION,
                                  PROP_VPI,
                                  PROP_VCI, );

typedef struct {
    char   *username;
    char   *password;
    char   *protocol;
    char   *encapsulation;
    guint   password_flags;
    guint32 vpi;
    guint32 vci;
} NMSettingAdslPrivate;

/**
 * NMSettingAdsl:
 *
 * ADSL Settings
 */
struct _NMSettingAdsl {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingAdslClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingAdsl, nm_setting_adsl, NM_TYPE_SETTING)

#define NM_SETTING_ADSL_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_ADSL, NMSettingAdslPrivate))

/*****************************************************************************/

/**
 * nm_setting_adsl_get_username:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:username property of the setting
 **/
const char *
nm_setting_adsl_get_username(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), NULL);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->username;
}

/**
 * nm_setting_adsl_get_password:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:password property of the setting
 **/
const char *
nm_setting_adsl_get_password(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), NULL);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->password;
}

/**
 * nm_setting_adsl_get_password_flags:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingAdsl:password
 **/
NMSettingSecretFlags
nm_setting_adsl_get_password_flags(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->password_flags;
}

/**
 * nm_setting_adsl_get_protocol:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:protocol property of the setting
 **/
const char *
nm_setting_adsl_get_protocol(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), NULL);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->protocol;
}

/**
 * nm_setting_adsl_get_encapsulation:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:encapsulation property of the setting
 **/
const char *
nm_setting_adsl_get_encapsulation(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), NULL);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->encapsulation;
}

/**
 * nm_setting_adsl_get_vpi:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:vpi property of the setting
 **/
guint32
nm_setting_adsl_get_vpi(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), 0);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->vpi;
}

/**
 * nm_setting_adsl_get_vci:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:vci property of the setting
 **/
guint32
nm_setting_adsl_get_vci(NMSettingAdsl *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_ADSL(setting), 0);

    return NM_SETTING_ADSL_GET_PRIVATE(setting)->vci;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingAdslPrivate *priv = NM_SETTING_ADSL_GET_PRIVATE(setting);

    if (!priv->username) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_MISSING_PROPERTY,
                            _("property is missing"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_USERNAME);
        return FALSE;
    }
    if (!priv->username[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_USERNAME);
        return FALSE;
    }

    if (!NM_IN_STRSET(priv->protocol,
                      NM_SETTING_ADSL_PROTOCOL_PPPOA,
                      NM_SETTING_ADSL_PROTOCOL_PPPOE,
                      NM_SETTING_ADSL_PROTOCOL_IPOATM)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid value for the property"),
                    priv->protocol ?: "(null)");
        g_prefix_error(error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_PROTOCOL);
        return FALSE;
    }

    if (!NM_IN_STRSET(priv->encapsulation,
                      NULL,
                      NM_SETTING_ADSL_ENCAPSULATION_VCMUX,
                      NM_SETTING_ADSL_ENCAPSULATION_LLC)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid value for the property"),
                    priv->encapsulation);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_ADSL_SETTING_NAME,
                       NM_SETTING_ADSL_ENCAPSULATION);
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify_secrets(NMSetting *setting, NMConnection *connection, GError **error)
{
    return _nm_setting_verify_secret_string(NM_SETTING_ADSL_GET_PRIVATE(setting)->password,
                                            NM_SETTING_ADSL_SETTING_NAME,
                                            NM_SETTING_ADSL_PASSWORD,
                                            error);
}

static GPtrArray *
need_secrets(NMSetting *setting, gboolean check_rerequest)
{
    NMSettingAdslPrivate *priv    = NM_SETTING_ADSL_GET_PRIVATE(setting);
    GPtrArray            *secrets = NULL;

    if (!check_rerequest && priv->password && *priv->password)
        return NULL;

    if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
        secrets = g_ptr_array_sized_new(1);
        g_ptr_array_add(secrets, NM_SETTING_ADSL_PASSWORD);
    }

    return secrets;
}

/*****************************************************************************/

static void
nm_setting_adsl_init(NMSettingAdsl *setting)
{}

/**
 * nm_setting_adsl_new:
 *
 * Creates a new #NMSettingAdsl object with default values.
 *
 * Returns: the new empty #NMSettingAdsl object
 **/
NMSetting *
nm_setting_adsl_new(void)
{
    return g_object_new(NM_TYPE_SETTING_ADSL, NULL);
}

static void
nm_setting_adsl_class_init(NMSettingAdslClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingAdslPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify         = verify;
    setting_class->verify_secrets = verify_secrets;
    setting_class->need_secrets   = need_secrets;

    /**
     * NMSettingAdsl:username:
     *
     * Username used to authenticate with the ADSL service.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_USERNAME,
                                              PROP_USERNAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingAdslPrivate,
                                              username);

    /**
     * NMSettingAdsl:password:
     *
     * Password used to authenticate with the ADSL service.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_PASSWORD,
                                              PROP_PASSWORD,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingAdslPrivate,
                                              password);

    /**
     * NMSettingAdsl:password-flags:
     *
     * Flags indicating how to handle the #NMSettingAdsl:password property.
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_ADSL_PASSWORD_FLAGS,
                                                    PROP_PASSWORD_FLAGS,
                                                    NMSettingAdslPrivate,
                                                    password_flags);

    /**
     * NMSettingAdsl:protocol:
     *
     * ADSL connection protocol.  Can be "pppoa", "pppoe" or "ipoatm".
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_PROTOCOL,
                                              PROP_PROTOCOL,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingAdslPrivate,
                                              protocol,
                                              .direct_set_string_ascii_strdown = TRUE);

    /**
     * NMSettingAdsl:encapsulation:
     *
     * Encapsulation of ADSL connection.  Can be "vcmux" or "llc".
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_ENCAPSULATION,
                                              PROP_ENCAPSULATION,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingAdslPrivate,
                                              encapsulation,
                                              .direct_set_string_ascii_strdown = TRUE);

    /**
     * NMSettingAdsl:vpi:
     *
     * VPI of ADSL connection
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_VPI,
                                              PROP_VPI,
                                              0,
                                              65536,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingAdslPrivate,
                                              vpi);

    /**
     * NMSettingAdsl:vci:
     *
     * VCI of ADSL connection
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_ADSL_VCI,
                                              PROP_VCI,
                                              0,
                                              65536,
                                              0,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingAdslPrivate,
                                              vci);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_ADSL,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
