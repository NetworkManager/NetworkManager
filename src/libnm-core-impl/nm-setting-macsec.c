/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-macsec.h"

#include <stdlib.h>

#include "libnm-glib-aux/nm-secret-utils.h"

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-setting-wired.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-macsec
 * @short_description: Describes connection properties for MACSEC interfaces
 *
 * The #NMSettingMacsec object is a #NMSetting subclass that describes properties
 * necessary for connection to MACsec (IEEE 802.1AE) interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PARENT,
                                  PROP_MODE,
                                  PROP_ENCRYPT,
                                  PROP_MKA_CAK,
                                  PROP_MKA_CAK_FLAGS,
                                  PROP_MKA_CKN,
                                  PROP_PORT,
                                  PROP_VALIDATION,
                                  PROP_SEND_SCI, );

typedef struct {
    char  *parent;
    char  *mka_cak;
    char  *mka_ckn;
    guint  mka_cak_flags;
    gint32 mode;
    gint32 validation;
    gint32 port;
    bool   encrypt;
    bool   send_sci;
} NMSettingMacsecPrivate;

/**
 * NMSettingMacsec:
 *
 * MACSec Settings
 */
struct _NMSettingMacsec {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingMacsecClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingMacsec, nm_setting_macsec, NM_TYPE_SETTING)

#define NM_SETTING_MACSEC_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_MACSEC, NMSettingMacsecPrivate))

/*****************************************************************************/

/**
 * nm_setting_macsec_get_parent:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:parent property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_parent(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NULL);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->parent;
}

/**
 * nm_setting_macsec_get_mode:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mode property of the setting
 *
 * Since: 1.6
 **/
NMSettingMacsecMode
nm_setting_macsec_get_mode(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NM_SETTING_MACSEC_MODE_PSK);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_macsec_get_encrypt:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:encrypt property of the setting
 *
 * Since: 1.6
 **/
gboolean
nm_setting_macsec_get_encrypt(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), TRUE);
    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->encrypt;
}

/**
 * nm_setting_macsec_get_mka_cak
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mka-cak property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_mka_cak(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NULL);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->mka_cak;
}

/**
 * nm_setting_macsec_get_mka_cak_flags:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingMacsec:mka-cak
 *
 * Since: 1.6
 **/
NMSettingSecretFlags
nm_setting_macsec_get_mka_cak_flags(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NM_SETTING_SECRET_FLAG_NONE);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->mka_cak_flags;
}

/**
 * nm_setting_macsec_get_mka_ckn:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mka-ckn property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_mka_ckn(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NULL);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->mka_ckn;
}

/**
 * nm_setting_macsec_get_port:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:port property of the setting
 *
 * Since: 1.6
 **/
int
nm_setting_macsec_get_port(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), 1);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->port;
}

/**
 * nm_setting_macsec_get_validation:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:validation property of the setting
 *
 * Since: 1.6
 **/
NMSettingMacsecValidation
nm_setting_macsec_get_validation(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), NM_SETTING_MACSEC_VALIDATION_DISABLE);

    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->validation;
}

/**
 * nm_setting_macsec_get_send_sci:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:send-sci property of the setting
 *
 * Since: 1.12
 **/
gboolean
nm_setting_macsec_get_send_sci(NMSettingMacsec *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_MACSEC(setting), TRUE);
    return NM_SETTING_MACSEC_GET_PRIVATE(setting)->send_sci;
}

static GPtrArray *
need_secrets(NMSetting *setting, gboolean check_rerequest)
{
    NMSettingMacsecPrivate *priv    = NM_SETTING_MACSEC_GET_PRIVATE(setting);
    GPtrArray              *secrets = NULL;

    if (priv->mode == NM_SETTING_MACSEC_MODE_PSK) {
        if ((check_rerequest || !priv->mka_cak)
            && !NM_FLAGS_HAS(priv->mka_cak_flags, NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
            secrets = g_ptr_array_sized_new(1);
            g_ptr_array_add(secrets, NM_SETTING_MACSEC_MKA_CAK);
        }
    }

    return secrets;
}

/*********************************************************************/

static gboolean
verify_macsec_key(const char *key, gboolean cak, GError **error)
{
    size_t len;

    /* CAK is a connection secret and can be NULL for various
     * reasons (agent-owned, no permissions to get secrets, etc.)
     */
    if (cak && !key)
        return TRUE;

    if (!key || !key[0]) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("the key is empty"));
        return FALSE;
    }

    len = strlen(key);
    if (cak) {
        if (len != NM_SETTING_MACSEC_MKA_CAK_LENGTH) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("the key must be %d characters"),
                        NM_SETTING_MACSEC_MKA_CAK_LENGTH);
            return FALSE;
        }
    } else {
        if (len < 2 || len > 64 || len % 2 != 0) {
            g_set_error_literal(
                error,
                NM_CONNECTION_ERROR,
                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                _("the key must have an even number of characters between 2 and 64"));
            return FALSE;
        }
    }

    if (!NM_STRCHAR_ALL(key, ch, g_ascii_isxdigit(ch))) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("the key contains non-hexadecimal characters"));
        return FALSE;
    }

    return TRUE;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingMacsecPrivate *priv    = NM_SETTING_MACSEC_GET_PRIVATE(setting);
    NMSettingConnection    *s_con   = NULL;
    NMSettingWired         *s_wired = NULL;
    NMSetting8021x         *s_8021x = NULL;

    if (connection) {
        s_con   = nm_connection_get_setting_connection(connection);
        s_wired = nm_connection_get_setting_wired(connection);
        s_8021x = nm_connection_get_setting_802_1x(connection);
    }

    if (priv->parent) {
        if (nm_utils_is_uuid(priv->parent)) {
            /* If we have an NMSettingConnection:master with slave-type="macsec",
             * then it must be the same UUID.
             */
            if (s_con) {
                const char *master = NULL, *slave_type = NULL;

                slave_type = nm_setting_connection_get_slave_type(s_con);
                if (!g_strcmp0(slave_type, NM_SETTING_MACSEC_SETTING_NAME))
                    master = nm_setting_connection_get_master(s_con);

                if (master && g_strcmp0(priv->parent, master) != 0) {
                    g_set_error(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("'%s' value doesn't match '%s=%s'"),
                                priv->parent,
                                NM_SETTING_CONNECTION_MASTER,
                                master);
                    g_prefix_error(error,
                                   "%s.%s: ",
                                   NM_SETTING_MACSEC_SETTING_NAME,
                                   NM_SETTING_MACSEC_PARENT);
                    return FALSE;
                }
            }
        } else if (!nm_utils_iface_valid_name(priv->parent)) {
            /* parent must be either a UUID or an interface name */
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s' is neither an UUID nor an interface name"),
                        priv->parent);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACSEC_SETTING_NAME,
                           NM_SETTING_MACSEC_PARENT);
            return FALSE;
        }
    } else {
        /* If parent is NULL, the parent must be specified via
         * NMSettingWired:mac-address.
         */
        if (connection && (!s_wired || !nm_setting_wired_get_mac_address(s_wired))) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_PROPERTY,
                        _("property is not specified and neither is '%s:%s'"),
                        NM_SETTING_WIRED_SETTING_NAME,
                        NM_SETTING_WIRED_MAC_ADDRESS);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACSEC_SETTING_NAME,
                           NM_SETTING_MACSEC_PARENT);
            return FALSE;
        }
    }

    if (priv->mode == NM_SETTING_MACSEC_MODE_PSK) {
        if (!verify_macsec_key(priv->mka_ckn, FALSE, error)) {
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACSEC_SETTING_NAME,
                           NM_SETTING_MACSEC_MKA_CKN);
            return FALSE;
        }
        if (!verify_macsec_key(priv->mka_cak, TRUE, error)) {
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_MACSEC_SETTING_NAME,
                           NM_SETTING_MACSEC_MKA_CAK);
            return FALSE;
        }
    } else if (priv->mode == NM_SETTING_MACSEC_MODE_EAP) {
        if (!s_8021x) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("EAP key management requires '%s' setting presence"),
                        NM_SETTING_802_1X_SETTING_NAME);
            g_prefix_error(error, "%s: ", NM_SETTING_MACSEC_SETTING_NAME);
            return FALSE;
        }
    } else {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("must be either psk (0) or eap (1)"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_MODE);
        return FALSE;
    }

    nm_assert(priv->port >= 1 && priv->port <= 65534);

    if (priv->mode != NM_SETTING_MACSEC_MODE_PSK && (priv->mka_cak || priv->mka_ckn)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("only valid for psk mode"));
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_MACSEC_SETTING_NAME,
                       priv->mka_cak ? NM_SETTING_MACSEC_MKA_CAK : NM_SETTING_MACSEC_MKA_CKN);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_macsec_init(NMSettingMacsec *self)
{}

/**
 * nm_setting_macsec_new:
 *
 * Creates a new #NMSettingMacsec object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMacsec object
 *
 * Since: 1.6
 **/
NMSetting *
nm_setting_macsec_new(void)
{
    return g_object_new(NM_TYPE_SETTING_MACSEC, NULL);
}

static void
nm_setting_macsec_class_init(NMSettingMacsecClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingMacsecPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify       = verify;
    setting_class->need_secrets = need_secrets;

    /**
     * NMSettingMacsec:parent:
     *
     * If given, specifies the parent interface name or parent connection UUID
     * from which this MACSEC interface should be created.  If this property is
     * not specified, the connection must contain an #NMSettingWired setting
     * with a #NMSettingWired:mac-address property.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_MACSEC_PARENT,
                                              PROP_PARENT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingMacsecPrivate,
                                              parent);

    /**
     * NMSettingMacsec:mode:
     *
     * Specifies how the CAK (Connectivity Association Key) for MKA (MACsec Key
     * Agreement) is obtained.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_MACSEC_MODE,
                                             PROP_MODE,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_MACSEC_MODE_PSK,
                                             NM_SETTING_PARAM_INFERRABLE,
                                             NMSettingMacsecPrivate,
                                             mode);

    /**
     * NMSettingMacsec:encrypt:
     *
     * Whether the transmitted traffic must be encrypted.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_MACSEC_ENCRYPT,
                                               PROP_ENCRYPT,
                                               TRUE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingMacsecPrivate,
                                               encrypt);

    /**
     * NMSettingMacsec:mka-cak:
     *
     * The pre-shared CAK (Connectivity Association Key) for MACsec
     * Key Agreement. Must be a string of 32 hexadecimal characters.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_MACSEC_MKA_CAK,
                                              PROP_MKA_CAK,
                                              NM_SETTING_PARAM_SECRET,
                                              NMSettingMacsecPrivate,
                                              mka_cak);

    /**
     * NMSettingMacsec:mka-cak-flags:
     *
     * Flags indicating how to handle the #NMSettingMacsec:mka-cak
     * property.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_secret_flags(properties_override,
                                                    obj_properties,
                                                    NM_SETTING_MACSEC_MKA_CAK_FLAGS,
                                                    PROP_MKA_CAK_FLAGS,
                                                    NMSettingMacsecPrivate,
                                                    mka_cak_flags);

    /**
     * NMSettingMacsec:mka-ckn:
     *
     * The pre-shared CKN (Connectivity-association Key Name) for
     * MACsec Key Agreement. Must be a string of hexadecimal characters
     * with a even length between 2 and 64.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_MACSEC_MKA_CKN,
                                              PROP_MKA_CKN,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingMacsecPrivate,
                                              mka_ckn);

    /**
     * NMSettingMacsec:port:
     *
     * The port component of the SCI (Secure Channel Identifier), between 1 and 65534.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_MACSEC_PORT,
                                             PROP_PORT,
                                             1,
                                             65534,
                                             1,
                                             NM_SETTING_PARAM_INFERRABLE,
                                             NMSettingMacsecPrivate,
                                             port);

    /**
     * NMSettingMacsec:validation:
     *
     * Specifies the validation mode for incoming frames.
     *
     * Since: 1.6
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_MACSEC_VALIDATION,
                                             PROP_VALIDATION,
                                             G_MININT32,
                                             G_MAXINT32,
                                             NM_SETTING_MACSEC_VALIDATION_STRICT,
                                             NM_SETTING_PARAM_INFERRABLE,
                                             NMSettingMacsecPrivate,
                                             validation);

    /**
     * NMSettingMacsec:send-sci:
     *
     * Specifies whether the SCI (Secure Channel Identifier) is included
     * in every packet.
     *
     * Since: 1.12
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_MACSEC_SEND_SCI,
                                               PROP_SEND_SCI,
                                               TRUE,
                                               NM_SETTING_PARAM_NONE,
                                               NMSettingMacsecPrivate,
                                               send_sci);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_MACSEC,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
