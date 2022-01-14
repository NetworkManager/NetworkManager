/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-tun.h"

#include <stdlib.h>

#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-tun
 * @short_description: Describes connection properties for TUN/TAP interfaces
 *
 * The #NMSettingTun object is a #NMSetting subclass that describes properties
 * necessary for connection to TUN/TAP interfaces.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_MODE,
                                  PROP_OWNER,
                                  PROP_GROUP,
                                  PROP_PI,
                                  PROP_VNET_HDR,
                                  PROP_MULTI_QUEUE, );

typedef struct {
    char   *owner;
    char   *group;
    guint32 mode;
    bool    pi;
    bool    vnet_hdr;
    bool    multi_queue;
} NMSettingTunPrivate;

/**
 * NMSettingTun:
 *
 * Tunnel Settings
 */
struct _NMSettingTun {
    NMSetting parent;
    /* In the past, this struct was public API. Preserve ABI! */
};

struct _NMSettingTunClass {
    NMSettingClass parent;
    /* In the past, this struct was public API. Preserve ABI! */
    gpointer padding[4];
};

G_DEFINE_TYPE(NMSettingTun, nm_setting_tun, NM_TYPE_SETTING)

#define NM_SETTING_TUN_GET_PRIVATE(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), NM_TYPE_SETTING_TUN, NMSettingTunPrivate))

/*****************************************************************************/

/**
 * nm_setting_tun_get_mode:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:mode property of the setting
 *
 * Since: 1.2
 **/
NMSettingTunMode
nm_setting_tun_get_mode(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), NM_SETTING_TUN_MODE_TUN);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->mode;
}

/**
 * nm_setting_tun_get_owner:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:owner property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_tun_get_owner(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), NULL);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->owner;
}

/**
 * nm_setting_tun_get_group:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:group property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_tun_get_group(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), NULL);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->group;
}

/**
 * nm_setting_tun_get_pi:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:pi property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_pi(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), FALSE);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->pi;
}

/**
 * nm_setting_tun_get_vnet_hdr:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:vnet_hdr property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_vnet_hdr(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), FALSE);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->vnet_hdr;
}

/**
 * nm_setting_tun_get_multi_queue:
 * @setting: the #NMSettingTun
 *
 * Returns: the #NMSettingTun:multi-queue property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_tun_get_multi_queue(NMSettingTun *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_TUN(setting), FALSE);
    return NM_SETTING_TUN_GET_PRIVATE(setting)->multi_queue;
}

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingTunPrivate *priv = NM_SETTING_TUN_GET_PRIVATE(setting);

    if (!NM_IN_SET(priv->mode, NM_SETTING_TUN_MODE_TUN, NM_SETTING_TUN_MODE_TAP)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%u': invalid mode"),
                    (unsigned) priv->mode);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_MODE);
        return FALSE;
    }

    if (priv->owner) {
        if (_nm_utils_ascii_str_to_int64(priv->owner, 10, 0, G_MAXINT32, -1) == -1) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s': invalid user ID"),
                        priv->owner);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_OWNER);
            return FALSE;
        }
    }

    if (priv->group) {
        if (_nm_utils_ascii_str_to_int64(priv->group, 10, 0, G_MAXINT32, -1) == -1) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("'%s': invalid group ID"),
                        priv->group);
            g_prefix_error(error, "%s.%s: ", NM_SETTING_TUN_SETTING_NAME, NM_SETTING_TUN_GROUP);
            return FALSE;
        }
    }

    return TRUE;
}

/*****************************************************************************/

static void
nm_setting_tun_init(NMSettingTun *self)
{}

/**
 * nm_setting_tun_new:
 *
 * Creates a new #NMSettingTun object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTun object
 *
 * Since: 1.2
 **/
NMSetting *
nm_setting_tun_new(void)
{
    return g_object_new(NM_TYPE_SETTING_TUN, NULL);
}

static void
nm_setting_tun_class_init(NMSettingTunClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    g_type_class_add_private(klass, sizeof(NMSettingTunPrivate));

    object_class->get_property = _nm_setting_property_get_property_direct;
    object_class->set_property = _nm_setting_property_set_property_direct;

    setting_class->verify = verify;

    /**
     * NMSettingTun:mode:
     *
     * The operating mode of the virtual device. Allowed values are
     * %NM_SETTING_TUN_MODE_TUN to create a layer 3 device and
     * %NM_SETTING_TUN_MODE_TAP to create an Ethernet-like layer 2
     * one.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_TUN_MODE,
                                              PROP_MODE,
                                              0,
                                              G_MAXUINT32,
                                              NM_SETTING_TUN_MODE_TUN,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingTunPrivate,
                                              mode);

    /**
     * NMSettingTun:owner:
     *
     * The user ID which will own the device. If set to %NULL everyone
     * will be able to use the device.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_TUN_OWNER,
                                              PROP_OWNER,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingTunPrivate,
                                              owner);

    /**
     * NMSettingTun:group:
     *
     * The group ID which will own the device. If set to %NULL everyone
     * will be able to use the device.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_TUN_GROUP,
                                              PROP_GROUP,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingTunPrivate,
                                              group);

    /**
     * NMSettingTun:pi:
     *
     * If %TRUE the interface will prepend a 4 byte header describing the
     * physical interface to the packets.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_TUN_PI,
                                               PROP_PI,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingTunPrivate,
                                               pi);

    /**
     * NMSettingTun:vnet-hdr:
     *
     * If %TRUE the IFF_VNET_HDR the tunnel packets will include a virtio
     * network header.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_TUN_VNET_HDR,
                                               PROP_VNET_HDR,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingTunPrivate,
                                               vnet_hdr);

    /**
     * NMSettingTun:multi-queue:
     *
     * If the property is set to %TRUE, the interface will support
     * multiple file descriptors (queues) to parallelize packet
     * sending or receiving. Otherwise, the interface will only
     * support a single queue.
     *
     * Since: 1.2
     */
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_TUN_MULTI_QUEUE,
                                               PROP_MULTI_QUEUE,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingTunPrivate,
                                               multi_queue);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_TUN,
                             NULL,
                             properties_override,
                             NM_SETT_INFO_PRIVATE_OFFSET_FROM_CLASS);
}
