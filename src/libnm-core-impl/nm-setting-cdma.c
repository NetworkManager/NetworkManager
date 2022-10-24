/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-cdma.h"

#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-cdma
 * @short_description: Describes CDMA-based mobile broadband properties
 *
 * The #NMSettingCdma object is a #NMSetting subclass that describes
 * properties that allow connections to IS-95-based mobile broadband
 * networks, including those using CDMA2000/EVDO technology.
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_NUMBER,
                                  PROP_USERNAME,
                                  PROP_PASSWORD,
                                  PROP_PASSWORD_FLAGS,
                                  PROP_MTU, );

typedef struct {
    char                *number;
    char                *username;
    char                *password;
    guint32              mtu;
    NMSettingSecretFlags password_flags;
} NMSettingCdmaPrivate;

/**
 * NMSettingCdma:
 *
 * CDMA-based Mobile Broadband Settings
 */
struct _NMSettingCdma {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingCdmaClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingCdma, nm_setting_cdma, NM_TYPE_SETTING)

#define NM_SETTING_CDMA_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_CDMA, NMSettingCdmaPrivate))

/*****************************************************************************/

/**
 * nm_setting_cdma_get_number:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:number property of the setting
 **/
const char *
nm_setting_cdma_get_number(NMSettingCdma *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CDMA(setting), NULL);

    return NM_SETTING_CDMA_GET_PRIVATE(setting)->number;
}

/**
 * nm_setting_cdma_get_username:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:username property of the setting
 **/
const char *
nm_setting_cdma_get_username(NMSettingCdma *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CDMA(setting), NULL);

    return NM_SETTING_CDMA_GET_PRIVATE(setting)->username;
}

/**
 * nm_setting_cdma_get_password:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:password property of the setting
 **/
const char *
nm_setting_cdma_get_password(NMSettingCdma *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CDMA(setting), NULL);

    return NM_SETTING_CDMA_GET_PRIVATE(setting)->password;
}

/**
 * nm_setting_cdma_get_password_flags:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingCdma:password
 **/
NMSettingSecretFlags
nm_setting_cdma_get_password_flags(NMSettingCdma *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CDMA(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_CDMA_GET_PRIVATE(setting)->password_flags;
}

/**
 * nm_setting_cdma_get_mtu:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:mtu property of the setting
 *
 * Since: 1.8
 **/
guint32
nm_setting_cdma_get_mtu(NMSettingCdma *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_CDMA(setting), 0);

    return NM_SETTING_CDMA_GET_PRIVATE(setting)->mtu;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingCdmaPrivate *priv = NM_SETTING_CDMA_GET_PRIVATE(setting);

    if (nm_str_is_empty(priv->number)) {
        if (!priv->number) {
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
        g_prefix_error(error, "%s.%s: ", NM_SETTING_CDMA_SETTING_NAME, NM_SETTING_CDMA_NUMBER);
        return FALSE;
    }

    if (priv->username && nm_str_is_empty(priv->username)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("property is empty"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_CDMA_SETTING_NAME, NM_SETTING_CDMA_USERNAME);
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify_secrets(NMSetting *setting, NMConnection *connection, GError **error)
{
    return _nm_setting_verify_secret_string(NM_SETTING_CDMA_GET_PRIVATE(setting)->password,
                                            NM_SETTING_CDMA_SETTING_NAME,
                                            NM_SETTING_CDMA_PASSWORD,
                                            error);
}

static GPtrArray *
need_secrets(NMSetting *setting, gboolean check_rerequest)
{
    NMSettingCdmaPrivate *priv    = NM_SETTING_CDMA_GET_PRIVATE(setting);
    GPtrArray            *secrets = NULL;

    if (!check_rerequest && !nm_str_is_empty(priv->password))
        return NULL;

    if (priv->username) {
        if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
            secrets = g_ptr_array_sized_new(1);
            g_ptr_array_add(secrets, NM_SETTING_CDMA_PASSWORD);
        }
    }

    return secrets;
}

/*****************************************************************************/

static void
nm_setting_cdma_init(NMSettingCdma *setting)
{}

/**
 * nm_setting_cdma_new:
 *
 * Creates a new #NMSettingCdma object with default values.
 *
 * Returns: the new empty #NMSettingCdma object
 **/
NMSetting *
nm_setting_cdma_new(void)
{
    return g_object_new(NM_TYPE_SETTING_CDMA, NULL);
}

static void
nm_setting_cdma_class_init(NMSettingCdmaClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingCdmaPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify         = verify;
    setting_class->verify_secrets = verify_secrets;
    setting_class->need_secrets   = need_secrets;

    /**
     * NMSettingCdma:number:
     *
     * The number to dial to establish the connection to the CDMA-based mobile
     * broadband network, if any.  If not specified, the default number (#777)
     * is used when required.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CDMA_NUMBER,
                                              PROP_NUMBER,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingCdmaPrivate,
                                              number);

    /**
     * NMSettingCdma:username:
     *
     * The username used to authenticate with the network, if required.  Many
     * providers do not require a username, or accept any username.  But if a
     * username is required, it is specified here.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CDMA_USERNAME,
                                              PROP_USERNAME,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingCdmaPrivate,
                                              username);

    /**
     * NMSettingCdma:password:
     *
     * The password used to authenticate with the network, if required.  Many
     * providers do not require a password, or accept any password.  But if a
     * password is required, it is specified here.
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_CDMA_PASSWORD,
                                              PROP_PASSWORD,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingCdmaPrivate,
                                              password);

    /**
     * NMSettingCdma:password-flags:
     *
     * Flags indicating how to handle the #NMSettingCdma:password property.
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_CDMA_PASSWORD_FLAGS,
                                                    PROP_PASSWORD_FLAGS,
                                                    NMSettingCdmaPrivate,
                                                    password_flags);

    /**
     * NMSettingCdma:mtu:
     *
     * If non-zero, only transmit packets of the specified size or smaller,
     * breaking larger packets up into multiple frames.
     *
     * Since: 1.8
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_CDMA_MTU,
                                              PROP_MTU,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_FUZZY_IGNORE,
                                              NMSettingCdmaPrivate,
                                              mtu);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_CDMA,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
