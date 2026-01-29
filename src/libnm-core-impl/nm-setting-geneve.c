/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2026 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-geneve.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-geneve
 * @short_description: Describes connection properties for GENEVE interfaces
 *
 * The #NMSettingGeneve object is a #NMSetting subclass that describes properties
 * necessary for connection to GENEVE interfaces.
 **/

#define DST_PORT_DEFAULT 6081

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_ID,
                                  PROP_REMOTE,
                                  PROP_DESTINATION_PORT,
                                  PROP_TOS,
                                  PROP_TTL,
                                  PROP_DF, );

typedef struct {
    char   *remote;
    guint32 id;
    guint32 destination_port;
    guint32 tos;
    gint32  ttl;
    int     df;
} NMSettingGenevePrivate;

/**
 * NMSettingGeneve:
 *
 * GENEVE Settings
 */
struct _NMSettingGeneve {
    NMSetting              parent;
    NMSettingGenevePrivate _priv;
};

struct _NMSettingGeneveClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingGeneve, nm_setting_geneve, NM_TYPE_SETTING)

#define NM_SETTING_GENEVE_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(o, NMSettingGeneve, NM_IS_SETTING_GENEVE, NMSetting)

/*****************************************************************************/

/**
 * nm_setting_geneve_get_id:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:id property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
guint
nm_setting_geneve_get_id(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), 0);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->id;
}

/**
 * nm_setting_geneve_get_remote:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:remote property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
const char *
nm_setting_geneve_get_remote(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), NULL);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->remote;
}

/**
 * nm_setting_geneve_get_destination_port:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:destination-port property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
guint
nm_setting_geneve_get_destination_port(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), DST_PORT_DEFAULT);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->destination_port;
}

/**
 * nm_setting_geneve_get_tos:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:tos property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
guint
nm_setting_geneve_get_tos(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), 0);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->tos;
}

/**
 * nm_setting_geneve_get_ttl:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:ttl property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
guint
nm_setting_geneve_get_ttl(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), 0);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->ttl;
}

/**
 * nm_setting_geneve_get_df:
 * @setting: the #NMSettingGeneve
 *
 * Returns: the #NMSettingGeneve:df property of the setting
 *
 * Since: 1.56, 1.54.4
 **/
NMSettingGeneveDf
nm_setting_geneve_get_df(NMSettingGeneve *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_GENEVE(setting), NM_SETTING_GENEVE_DF_UNSET);

    return NM_SETTING_GENEVE_GET_PRIVATE(setting)->df;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingGenevePrivate *priv = NM_SETTING_GENEVE_GET_PRIVATE(setting);

    if (priv->id == 0) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("property is required"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GENEVE_SETTING_NAME, NM_SETTING_GENEVE_ID);
        return FALSE;
    }

    if (!priv->remote) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_MISSING_PROPERTY,
                    _("property is required"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GENEVE_SETTING_NAME, NM_SETTING_GENEVE_REMOTE);
        return FALSE;
    }

    if (!nm_inet_parse_bin(AF_UNSPEC, priv->remote, NULL, NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not a valid IP address"),
                    priv->remote);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_GENEVE_SETTING_NAME, NM_SETTING_GENEVE_REMOTE);
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_geneve_init(NMSettingGeneve *self)
{}

/**
 * nm_setting_geneve_new:
 *
 * Creates a new #NMSettingGeneve object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingGeneve object
 *
 * Since: 1.56, 1.54.4
 **/
NMSetting *
nm_setting_geneve_new(void)
{
    return g_object_new(NM_TYPE_SETTING_GENEVE, NULL);
}

static void
nm_setting_geneve_class_init(NMSettingGeneveClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingGeneve:id:
     *
     * Specifies the GENEVE Network Identifier (or GENEVE Segment Identifier) to
     * use.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_GENEVE_ID,
                                              PROP_ID,
                                              0,
                                              (1 << 24) - 1,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingGenevePrivate,
                                              id);

    /**
     * NMSettingGeneve:remote:
     *
     * Specifies the unicast destination IP address to use in outgoing packets
     * when communicating with the remote GENEVE tunnel endpoint.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_GENEVE_REMOTE,
                                              PROP_REMOTE,
                                              NM_SETTING_PARAM_REQUIRED,
                                              NMSettingGenevePrivate,
                                              remote,
                                              .direct_set_string_ip_address_addr_family =
                                                  AF_UNSPEC + 1,
                                              .direct_string_allow_empty = TRUE);

    /**
     * NMSettingGeneve:destination-port:
     *
     * Specifies the UDP destination port to communicate to the remote GENEVE
     * tunnel endpoint.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_GENEVE_DESTINATION_PORT,
                                              PROP_DESTINATION_PORT,
                                              0,
                                              G_MAXUINT16,
                                              DST_PORT_DEFAULT,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingGenevePrivate,
                                              destination_port);

    /**
     * NMSettingGeneve:tos:
     *
     * Specifies the TOS value to use in outgoing packets.
     * The special value "inherit" (1) means inherit from outer packet.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_GENEVE_TOS,
                                              PROP_TOS,
                                              0,
                                              255,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingGenevePrivate,
                                              tos);

    /**
     * NMSettingGeneve:ttl:
     *
     * Specifies the time-to-live value to use in outgoing packets.
     * The special value "inherit" (-1) means inherit from outer packet, 0 means auto, 1-255 are fixed values.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_int32(properties_override,
                                             obj_properties,
                                             NM_SETTING_GENEVE_TTL,
                                             PROP_TTL,
                                             -1,
                                             255,
                                             0,
                                             NM_SETTING_PARAM_INFERRABLE,
                                             NMSettingGenevePrivate,
                                             ttl);

    /**
     * NMSettingGeneve:df:
     *
     * Specifies how the Don't Fragment (DF) flag should be handled in the outer IP
     * header of GENEVE tunnel packets.
     *
     * %NM_SETTING_GENEVE_DF_UNSET (0): Don't set the DF flag, packets may be fragmented.
     * %NM_SETTING_GENEVE_DF_SET (1): Always set the DF flag, packets will not be fragmented.
     * %NM_SETTING_GENEVE_DF_INHERIT (2): Inherit the DF flag from the inner IP header.
     *
     * Since: 1.56, 1.54.4
     **/
    _nm_setting_property_define_direct_enum(properties_override,
                                            obj_properties,
                                            NM_SETTING_GENEVE_DF,
                                            PROP_DF,
                                            NM_TYPE_SETTING_GENEVE_DF,
                                            NM_SETTING_GENEVE_DF_UNSET,
                                            NM_SETTING_PARAM_INFERRABLE,
                                            NULL,
                                            NMSettingGenevePrivate,
                                            df);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_GENEVE,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingGeneve, _priv));
}
