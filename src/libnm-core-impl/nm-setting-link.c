/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-link.h"

#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-link
 * @short_description: Contains properties related to the link
 * @include: nm-setting-link.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingLink,
                             PROP_TX_QUEUE_LENGTH,
                             PROP_GSO_MAX_SIZE,
                             PROP_GSO_MAX_SEGMENTS,
                             PROP_GRO_MAX_SIZE,
                             PROP_ADMIN_STATE, );

/**
 * NMSettingLink:
 *
 * Link settings
 *
 * Since: 1.44
 */
struct _NMSettingLink {
    NMSetting parent;
    gint64    tx_queue_length;
    gint64    gso_max_size;
    gint64    gso_max_segments;
    gint64    gro_max_size;
    int       admin_state;
};

struct _NMSettingLinkClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingLink, nm_setting_link, NM_TYPE_SETTING)

/**
 * nm_setting_link_get_tx_queue_length:
 * @setting: the #NMSettingLink
 *
 * Returns the value contained in the #NMSettingLink:tx-queue-length
 * property.
 *
 * Returns: the 'tx-queue-length' property value
 *
 * Since: 1.44
 **/
gint64
nm_setting_link_get_tx_queue_length(NMSettingLink *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LINK(setting), 0);

    return setting->tx_queue_length;
}

/**
 * nm_setting_link_get_gso_max_size:
 * @setting: the #NMSettingLink
 *
 * Returns the value contained in the #NMSettingLink:gso-max-size
 * property.
 *
 * Returns: the 'gso-max-size' property value
 *
 * Since: 1.44
 **/
gint64
nm_setting_link_get_gso_max_size(NMSettingLink *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LINK(setting), 0);

    return setting->gso_max_size;
}

/**
 * nm_setting_link_get_gso_max_segments:
 * @setting: the #NMSettingLink
 *
 * Returns the value contained in the #NMSettingLink:gso-max-segments
 * property.
 *
 * Returns: the 'gso-max-segments' property value
 *
 * Since: 1.44
 **/
gint64
nm_setting_link_get_gso_max_segments(NMSettingLink *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LINK(setting), 0);

    return setting->gso_max_segments;
}

/**
 * nm_setting_link_get_gro_max_size:
 * @setting: the #NMSettingLink
 *
 * Returns the value contained in the #NMSettingLink:gro-max-size
 * property.
 *
 * Returns: the 'gro-max-size' property value
 *
 * Since: 1.44
 **/
gint64
nm_setting_link_get_gro_max_size(NMSettingLink *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LINK(setting), 0);

    return setting->gro_max_size;
}

/**
 * nm_setting_link_get_admin_state:
 * @setting: the #NMSettingLink
 *
 * Returns: the requested administrative state of the link
 *
 * Since: 1.60
 **/
NMSettingLinkAdminState
nm_setting_link_get_admin_state(NMSettingLink *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_LINK(setting), NM_SETTING_LINK_ADMIN_STATE_UP);

    return setting->admin_state;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingLink *self = NM_SETTING_LINK(setting);
    int            IS_IPv4;

    if (!NM_IN_SET(self->admin_state,
                   NM_SETTING_LINK_ADMIN_STATE_UP,
                   NM_SETTING_LINK_ADMIN_STATE_DOWN)) {
        g_set_error_literal(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("invalid value"));
        g_prefix_error(error, "%s.%s: ", NM_SETTING_LINK_SETTING_NAME, NM_SETTING_LINK_ADMIN_STATE);
        return FALSE;
    }

    if (self->admin_state == NM_SETTING_LINK_ADMIN_STATE_DOWN && connection) {
        for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
            NMSettingIPConfig *s_ip =
                nm_connection_get_setting_ip_config(connection, IS_IPv4 ? AF_INET : AF_INET6);
            const char *method;

            if (!s_ip)
                continue;

            method = nm_setting_ip_config_get_method(s_ip);
            if (!nm_streq0(method,
                           IS_IPv4 ? NM_SETTING_IP4_CONFIG_METHOD_DISABLED
                                   : NM_SETTING_IP6_CONFIG_METHOD_DISABLED)) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("method must be \"%s\" when %s.%s is \"down\""),
                            IS_IPv4 ? NM_SETTING_IP4_CONFIG_METHOD_DISABLED
                                    : NM_SETTING_IP6_CONFIG_METHOD_DISABLED,
                            NM_SETTING_LINK_SETTING_NAME,
                            NM_SETTING_LINK_ADMIN_STATE);
                g_prefix_error(error,
                               "%s.%s: ",
                               nm_setting_get_name(NM_SETTING(s_ip)),
                               NM_SETTING_IP_CONFIG_METHOD);
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_link_init(NMSettingLink *setting)
{}

/**
 * nm_setting_link_new:
 *
 * Creates a new #NMSettingLink object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingLink object
 *
 * Since: 1.44
 **/
NMSetting *
nm_setting_link_new(void)
{
    return g_object_new(NM_TYPE_SETTING_LINK, NULL);
}

static void
nm_setting_link_class_init(NMSettingLinkClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingLink:tx-queue-length
     *
     * The size of the transmit queue for the device, in number of packets. The value
     * must be between 0 and 4294967295. When set to -1, the existing value is preserved.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_int64(properties_override,
                                             obj_properties,
                                             NM_SETTING_LINK_TX_QUEUE_LENGTH,
                                             PROP_TX_QUEUE_LENGTH,
                                             -1,
                                             G_MAXUINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingLink,
                                             tx_queue_length);

    /**
     * NMSettingLink:gso-max-size
     *
     * The maximum size of a Generic Segment Offload packet the device should accept.
     * The value must be between 0 and 4294967295. When set to -1, the existing value
     * is preserved.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_int64(properties_override,
                                             obj_properties,
                                             NM_SETTING_LINK_GSO_MAX_SIZE,
                                             PROP_GSO_MAX_SIZE,
                                             -1,
                                             G_MAXUINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingLink,
                                             gso_max_size);

    /**
     * NMSettingLink:gso-max-segments
     *
     * The maximum segments of a Generic Segment Offload packet the device should accept.
     * The value must be between 0 and 4294967295. When set to -1, the existing value
     * is preserved.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_int64(properties_override,
                                             obj_properties,
                                             NM_SETTING_LINK_GSO_MAX_SEGMENTS,
                                             PROP_GSO_MAX_SEGMENTS,
                                             -1,
                                             G_MAXUINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingLink,
                                             gso_max_segments);

    /**
     * NMSettingLink:gro-max-size
     *
     * The maximum size of a packet built by the Generic Receive Offload stack for
     * this device. The value must be between 0 and 4294967295. When set to -1, the
     * existing value is preserved.
     *
     * Since: 1.44
     **/
    _nm_setting_property_define_direct_int64(properties_override,
                                             obj_properties,
                                             NM_SETTING_LINK_GRO_MAX_SIZE,
                                             PROP_GRO_MAX_SIZE,
                                             -1,
                                             G_MAXUINT32,
                                             -1,
                                             NM_SETTING_PARAM_NONE,
                                             NMSettingLink,
                                             gro_max_size);

    /**
     * NMSettingLink:admin-state
     *
     * The administrative state to apply to the link on activation or reapply.
     * The default is %NM_SETTING_LINK_ADMIN_STATE_UP.
     *
     * With %NM_SETTING_LINK_ADMIN_STATE_DOWN, both IP methods must be "disabled".
     * Omitted IP settings default to "disabled".
     *
     * Use "down" in nmcli and "admin-state=0" in the [link] section of a keyfile.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_enum(properties_override,
                                            obj_properties,
                                            NM_SETTING_LINK_ADMIN_STATE,
                                            PROP_ADMIN_STATE,
                                            NM_TYPE_SETTING_LINK_ADMIN_STATE,
                                            NM_SETTING_LINK_ADMIN_STATE_UP,
                                            NM_SETTING_PARAM_NONE,
                                            NULL,
                                            NMSettingLink,
                                            admin_state);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_LINK,
                             NULL,
                             properties_override,
                             0);
}
