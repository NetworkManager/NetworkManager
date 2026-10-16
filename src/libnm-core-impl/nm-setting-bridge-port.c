/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2012 - 2013 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-bridge-port.h"

#include <ctype.h>
#include <stdlib.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-bridge.h"

/**
 * SECTION:nm-setting-bridge-port
 * @short_description: Describes connection properties for bridge ports
 *
 * The #NMSettingBridgePort object is a #NMSetting subclass that describes
 * optional properties that apply to bridge ports.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingBridgePort,
                             PROP_PRIORITY,
                             PROP_PATH_COST,
                             PROP_BPDU_GUARD,
                             PROP_BROADCAST_FLOOD,
                             PROP_FAST_LEAVE,
                             PROP_HAIRPIN_MODE,
                             PROP_ISOLATED,
                             PROP_LEARNING,
                             PROP_LOCKED,
                             PROP_MULTICAST_FLOOD,
                             PROP_MULTICAST_TO_UNICAST,
                             PROP_NEIGHBOR_SUPPRESS,
                             PROP_NEIGHBOR_VLAN_SUPPRESS,
                             PROP_ROOT_BLOCK,
                             PROP_UNICAST_FLOOD,
                             PROP_VLAN_TUNNEL,
                             PROP_VLANS, );

typedef struct {
    GPtrArray *vlans;
    guint32    priority;
    guint32    path_cost;
    bool       bpdu_guard;
    bool       broadcast_flood;
    bool       fast_leave;
    bool       hairpin_mode;
    bool       isolated;
    bool       learning;
    bool       locked;
    bool       multicast_flood;
    bool       multicast_to_unicast;
    bool       neighbor_suppress;
    bool       neighbor_vlan_suppress;
    bool       root_block;
    bool       unicast_flood;
    bool       vlan_tunnel;
} NMSettingBridgePortPrivate;

/**
 * NMSettingBridgePort:
 *
 * Bridge Port Settings
 */
struct _NMSettingBridgePort {
    NMSetting                  parent;
    NMSettingBridgePortPrivate _priv;
};

struct _NMSettingBridgePortClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingBridgePort, nm_setting_bridge_port, NM_TYPE_SETTING)

#define NM_SETTING_BRIDGE_PORT_GET_PRIVATE(o) \
    _NM_GET_PRIVATE(o, NMSettingBridgePort, NM_IS_SETTING_BRIDGE_PORT, NMSetting)

/*****************************************************************************/

static int
vlan_ptr_cmp(gconstpointer a, gconstpointer b)
{
    const NMBridgeVlan *vlan_a = *(const NMBridgeVlan **) a;
    const NMBridgeVlan *vlan_b = *(const NMBridgeVlan **) b;

    return nm_bridge_vlan_cmp(vlan_a, vlan_b);
}

gboolean
_nm_setting_bridge_port_sort_vlans(NMSettingBridgePort *setting)
{
    NMSettingBridgePortPrivate *priv;
    gboolean                    need_sort = FALSE;
    guint                       i;

    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    for (i = 1; i < priv->vlans->len; i++) {
        NMBridgeVlan *vlan_prev = priv->vlans->pdata[i - 1];
        NMBridgeVlan *vlan      = priv->vlans->pdata[i];

        if (nm_bridge_vlan_cmp(vlan_prev, vlan) > 0) {
            need_sort = TRUE;
            break;
        }
    }

    if (need_sort) {
        g_ptr_array_sort(priv->vlans, vlan_ptr_cmp);
        _notify(setting, PROP_VLANS);
    }

    return need_sort;
}

/*****************************************************************************/

/**
 * nm_setting_bridge_port_get_priority:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:priority property of the setting
 **/
guint16
nm_setting_bridge_port_get_priority(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), 0);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->priority;
}

/**
 * nm_setting_bridge_port_get_path_cost:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:path-cost property of the setting
 **/
guint16
nm_setting_bridge_port_get_path_cost(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), 0);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->path_cost;
}

/**
 * nm_setting_bridge_port_get_bpdu_guard:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:bpdu-guard property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_bpdu_guard(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->bpdu_guard;
}

/**
 * nm_setting_bridge_port_get_broadcast_flood:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:broadcast-flood property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_broadcast_flood(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), TRUE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->broadcast_flood;
}

/**
 * nm_setting_bridge_port_get_fast_leave:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:fast-leave property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_fast_leave(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->fast_leave;
}

/**
 * nm_setting_bridge_port_get_hairpin_mode:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:hairpin-mode property of the setting
 **/
gboolean
nm_setting_bridge_port_get_hairpin_mode(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->hairpin_mode;
}

/**
 * nm_setting_bridge_port_get_isolated:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:isolated property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_isolated(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->isolated;
}

/**
 * nm_setting_bridge_port_get_learning:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:learning property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_learning(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), TRUE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->learning;
}

/**
 * nm_setting_bridge_port_get_locked:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:locked property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_locked(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->locked;
}

/**
 * nm_setting_bridge_port_get_multicast_flood:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:multicast-flood property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_multicast_flood(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), TRUE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->multicast_flood;
}

/**
 * nm_setting_bridge_port_get_multicast_to_unicast:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:multicast-to-unicast property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_multicast_to_unicast(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->multicast_to_unicast;
}

/**
 * nm_setting_bridge_port_get_neighbor_suppress:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:neighbor-suppress property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_neighbor_suppress(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->neighbor_suppress;
}

/**
 * nm_setting_bridge_port_get_neighbor_vlan_suppress:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:neighbor-vlan-suppress property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_neighbor_vlan_suppress(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->neighbor_vlan_suppress;
}

/**
 * nm_setting_bridge_port_get_root_block:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:root-block property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_root_block(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->root_block;
}

/**
 * nm_setting_bridge_port_get_unicast_flood:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:unicast-flood property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_unicast_flood(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), TRUE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->unicast_flood;
}

/**
 * nm_setting_bridge_port_get_vlan_tunnel:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the #NMSettingBridgePort:vlan-tunnel property of the setting
 *
 * Since: 1.60
 **/
gboolean
nm_setting_bridge_port_get_vlan_tunnel(NMSettingBridgePort *setting)
{
    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->vlan_tunnel;
}

/**
 * nm_setting_bridge_port_add_vlan:
 * @setting: the #NMSettingBridgePort
 * @vlan: the vlan to add
 *
 * Appends a new vlan and associated information to the setting.  The
 * given vlan gets sealed and a reference to it is added.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_port_add_vlan(NMSettingBridgePort *setting, NMBridgeVlan *vlan)
{
    NMSettingBridgePortPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting));
    g_return_if_fail(vlan);

    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    nm_bridge_vlan_seal(vlan);
    nm_bridge_vlan_ref(vlan);

    g_ptr_array_add(priv->vlans, vlan);
    _notify(setting, PROP_VLANS);
}

/**
 * nm_setting_bridge_port_get_num_vlans:
 * @setting: the #NMSettingBridgePort
 *
 * Returns: the number of VLANs
 *
 * Since: 1.18
 **/
guint
nm_setting_bridge_port_get_num_vlans(NMSettingBridgePort *setting)
{
    NMSettingBridgePortPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), 0);
    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    return priv->vlans->len;
}

/**
 * nm_setting_bridge_port_get_vlan:
 * @setting: the #NMSettingBridgePort
 * @idx: index number of the VLAN to return
 *
 * Returns: (transfer none): the VLAN at index @idx
 *
 * Since: 1.18
 **/
NMBridgeVlan *
nm_setting_bridge_port_get_vlan(NMSettingBridgePort *setting, guint idx)
{
    NMSettingBridgePortPrivate *priv;

    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), NULL);
    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    g_return_val_if_fail(idx < priv->vlans->len, NULL);

    return priv->vlans->pdata[idx];
}

/**
 * nm_setting_bridge_port_remove_vlan:
 * @setting: the #NMSettingBridgePort
 * @idx: index number of the VLAN.
 *
 * Removes the vlan at index @idx.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_port_remove_vlan(NMSettingBridgePort *setting, guint idx)
{
    NMSettingBridgePortPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting));
    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    g_return_if_fail(idx < priv->vlans->len);

    g_ptr_array_remove_index(priv->vlans, idx);
    _notify(setting, PROP_VLANS);
}

/**
 * nm_setting_bridge_port_remove_vlan_by_vid:
 * @setting: the #NMSettingBridgePort
 * @vid_start: the vlan start index
 * @vid_end: the vlan end index
 *
 * Remove the VLAN with range @vid_start to @vid_end.
 * If @vid_end is zero, it is assumed to be equal to @vid_start
 * and so the single-id VLAN with id @vid_start is removed.
 *
 * Returns: %TRUE if the vlan was found and removed; %FALSE otherwise
 *
 * Since: 1.18
 **/
gboolean
nm_setting_bridge_port_remove_vlan_by_vid(NMSettingBridgePort *setting,
                                          guint16              vid_start,
                                          guint16              vid_end)
{
    NMSettingBridgePortPrivate *priv;
    guint                       i;

    if (vid_end == 0)
        vid_end = vid_start;

    g_return_val_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting), FALSE);

    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    for (i = 0; i < priv->vlans->len; i++) {
        NMBridgeVlan *vlan    = priv->vlans->pdata[i];
        guint16       v_start = 0;
        guint16       v_end   = 0;

        nm_bridge_vlan_get_vid_range(vlan, &v_start, &v_end);
        if (v_start == vid_start && v_end == vid_end) {
            g_ptr_array_remove_index(priv->vlans, i);
            _notify(setting, PROP_VLANS);
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * nm_setting_bridge_port_clear_vlans:
 * @setting: the #NMSettingBridgePort
 *
 * Removes all configured VLANs.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_port_clear_vlans(NMSettingBridgePort *setting)
{
    NMSettingBridgePortPrivate *priv;

    g_return_if_fail(NM_IS_SETTING_BRIDGE_PORT(setting));
    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    if (priv->vlans->len != 0) {
        g_ptr_array_set_size(priv->vlans, 0);
        _notify(setting, PROP_VLANS);
    }
}

GPtrArray *
_nm_setting_bridge_port_get_vlans(NMSettingBridgePort *setting)
{
    nm_assert(NM_IS_SETTING_BRIDGE_PORT(setting));

    return NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting)->vlans;
}

/*****************************************************************************/

static gboolean
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingBridgePortPrivate *priv;

    priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    if (connection) {
        NMSettingConnection *s_con;
        const char          *port_type;

        s_con = nm_connection_get_setting_connection(connection);
        if (!s_con) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("missing setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
            return FALSE;
        }

        port_type = nm_setting_connection_get_port_type(s_con);
        if (port_type && strcmp(port_type, NM_SETTING_BRIDGE_SETTING_NAME)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have the port-type set to '%s'. "
                          "Instead it is '%s'"),
                        NM_SETTING_BRIDGE_PORT_SETTING_NAME,
                        NM_SETTING_BRIDGE_SETTING_NAME,
                        port_type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_PORT_TYPE);
            return FALSE;
        }
    }

    if (!_nm_utils_bridge_vlan_verify_list(priv->vlans,
                                           FALSE,
                                           error,
                                           NM_SETTING_BRIDGE_PORT_SETTING_NAME,
                                           NM_SETTING_BRIDGE_PORT_VLANS))
        return FALSE;

    /* Failures from here on are NORMALIZABLE... */

    if (!_nm_utils_bridge_vlan_verify_list(priv->vlans,
                                           TRUE,
                                           error,
                                           NM_SETTING_BRIDGE_PORT_SETTING_NAME,
                                           NM_SETTING_BRIDGE_PORT_VLANS))
        return NM_SETTING_VERIFY_NORMALIZABLE;

    return TRUE;
}

static NMTernary
compare_fcn_vlans(_NM_SETT_INFO_PROP_COMPARE_FCN_ARGS _nm_nil)
{
    if (set_b) {
        return _nm_utils_bridge_compare_vlans(NM_SETTING_BRIDGE_PORT_GET_PRIVATE(set_a)->vlans,
                                              NM_SETTING_BRIDGE_PORT_GET_PRIVATE(set_b)->vlans);
    }
    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_VLANS:
        g_value_take_boxed(value,
                           _nm_utils_copy_array(priv->vlans,
                                                (NMUtilsCopyFunc) nm_bridge_vlan_ref,
                                                (GDestroyNotify) nm_bridge_vlan_unref));
        break;
    default:
        _nm_setting_property_get_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_VLANS:
        g_ptr_array_unref(priv->vlans);
        priv->vlans = _nm_utils_copy_array(g_value_get_boxed(value),
                                           (NMUtilsCopyFunc) _nm_bridge_vlan_dup_and_seal,
                                           (GDestroyNotify) nm_bridge_vlan_unref);
        break;
    default:
        _nm_setting_property_set_property_direct(object, prop_id, value, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_setting_bridge_port_init(NMSettingBridgePort *setting)
{
    NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(setting);

    priv->vlans = g_ptr_array_new_with_free_func((GDestroyNotify) nm_bridge_vlan_unref);
}

/**
 * nm_setting_bridge_port_new:
 *
 * Creates a new #NMSettingBridgePort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBridgePort object
 **/
NMSetting *
nm_setting_bridge_port_new(void)
{
    return g_object_new(NM_TYPE_SETTING_BRIDGE_PORT, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingBridgePortPrivate *priv = NM_SETTING_BRIDGE_PORT_GET_PRIVATE(object);

    g_ptr_array_unref(priv->vlans);

    G_OBJECT_CLASS(nm_setting_bridge_port_parent_class)->finalize(object);
}

static void
nm_setting_bridge_port_class_init(NMSettingBridgePortClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingBridgePort:priority:
     *
     * The Spanning Tree Protocol (STP) priority of this bridge port.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_BRIDGE_PORT_PRIORITY,
                                              PROP_PRIORITY,
                                              NM_BRIDGE_PORT_PRIORITY_MIN,
                                              NM_BRIDGE_PORT_PRIORITY_MAX,
                                              NM_BRIDGE_PORT_PRIORITY_DEF,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingBridgePortPrivate,
                                              priority);

    /**
     * NMSettingBridgePort:path-cost:
     *
     * The Spanning Tree Protocol (STP) port cost for destinations via this
     * port.
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_BRIDGE_PORT_PATH_COST,
                                              PROP_PATH_COST,
                                              NM_BRIDGE_PORT_PATH_COST_MIN,
                                              NM_BRIDGE_PORT_PATH_COST_MAX,
                                              NM_BRIDGE_PORT_PATH_COST_DEF,
                                              NM_SETTING_PARAM_NONE,
                                              NMSettingBridgePortPrivate,
                                              path_cost);

    /**
     * NMSettingBridgePort:bpdu-guard:
     *
     * Controls whether STP BPDU packets will be processed by the bridge port.
     * By default, the flag is turned off, allowing BPDU processing. Turning this
     * flag on will disable the bridge port if a STP BPDU packet is received.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_BPDU_GUARD,
                                               PROP_BPDU_GUARD,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               bpdu_guard);

    /**
     * NMSettingBridgePort:broadcast-flood:
     *
     * Controls whether broadcast traffic is flooded to the port. By default,
     * the flag is on.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_BROADCAST_FLOOD,
                                               PROP_BROADCAST_FLOOD,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               broadcast_flood);

    /**
     * NMSettingBridgePort:fast-leave:
     *
     * Controls whether the bridge immediately stops forwarding multicast
     * traffic on the port when an IGMP leave message is received. This option
     * only has effect when IGMP snooping is enabled on the bridge. By default,
     * the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_FAST_LEAVE,
                                               PROP_FAST_LEAVE,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               fast_leave);

    /**
     * NMSettingBridgePort:hairpin-mode:
     *
     * Enables or disables "hairpin mode" for the port, which allows frames to
     * be sent back out through the port the frame was received on. By default,
     * this flag is off.
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE,
                                               PROP_HAIRPIN_MODE,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               hairpin_mode);

    /**
     * NMSettingBridgePort:isolated:
     *
     * Controls whether the port is isolated, which means that it can
     * communicate with non-isolated ports only. By default, the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_ISOLATED,
                                               PROP_ISOLATED,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               isolated);

    /**
     * NMSettingBridgePort:learning:
     *
     * Controls whether the port learns MAC addresses from received traffic. If
     * disabled, the bridge floods any traffic for which it has no forwarding
     * database (FDB) entry. By default, the flag is on.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_LEARNING,
                                               PROP_LEARNING,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               learning);

    /**
     * NMSettingBridgePort:locked:
     *
     * Controls whether the port is locked. When enabled, frames received
     * through the port are dropped unless a forwarding database (FDB) entry
     * with the source MAC address points to the port. This is typically used
     * for IEEE 802.1X authentication, where the user space control plane
     * installs an FDB entry after a host authenticates. Note that the learning
     * property is true by default, and a locked port still learns the source
     * MAC address of link-local frames (including the EAPOL ones used by
     * 802.1X) unless the bridge has the no_linklocal_learn option enabled.
     * Therefore, the 802.1X setup described above needs learning to be set to
     * false, or the no_linklocal_learn option to be configured externally on
     * the bridge (NetworkManager doesn't support it). By default, the flag
     * is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_LOCKED,
                                               PROP_LOCKED,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               locked);

    /**
     * NMSettingBridgePort:multicast-flood:
     *
     * Controls whether multicast traffic for which there is no multicast
     * database (MDB) entry is flooded to the port. By default, the flag is on.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_MULTICAST_FLOOD,
                                               PROP_MULTICAST_FLOOD,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               multicast_flood);

    /**
     * NMSettingBridgePort:multicast-to-unicast:
     *
     * Controls whether the port replicates multicast packets as unicast, by
     * copying the packet for each host and replacing the multicast destination
     * MAC address with the unicast one. Only hosts that signaled interest in
     * the multicast group through IGMP/MLD reports receive the packets. By
     * default, the flag is off. This is intended for interfaces, such as
     * Wi-Fi, that deliver unicast packets more reliably or efficiently than
     * multicast ones.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_MULTICAST_TO_UNICAST,
                                               PROP_MULTICAST_TO_UNICAST,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               multicast_to_unicast);

    /**
     * NMSettingBridgePort:neighbor-suppress:
     *
     * Controls whether neighbor discovery (ARP and ND) proxy and suppression
     * are enabled on the port. By default, the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_NEIGHBOR_SUPPRESS,
                                               PROP_NEIGHBOR_SUPPRESS,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               neighbor_suppress);

    /**
     * NMSettingBridgePort:neighbor-vlan-suppress:
     *
     * Controls whether per-VLAN neighbor discovery (ARP and ND) proxy and
     * suppression are enabled on the port. When enabled, the neighbor-suppress
     * option of the bridge port has no effect and the per-VLAN state is set
     * through the VLAN neighbor-suppress option. By default, the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_NEIGHBOR_VLAN_SUPPRESS,
                                               PROP_NEIGHBOR_VLAN_SUPPRESS,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               neighbor_vlan_suppress);

    /**
     * NMSettingBridgePort:root-block:
     *
     * Controls whether the port is allowed to become the root port in a
     * Spanning Tree Protocol (STP) topology. This option only has effect
     * when STP is enabled on the bridge. When enabled, if a superior BPDU
     * is received on this port, the port is blocked instead of being
     * elected as the root port. This prevents a downstream or rogue device
     * from hijacking the root bridge role and improperly rerouting network
     * traffic. By default, the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_ROOT_BLOCK,
                                               PROP_ROOT_BLOCK,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               root_block);

    /**
     * NMSettingBridgePort:unicast-flood:
     *
     * Controls whether unicast traffic for which there is no forwarding
     * database (FDB) entry is flooded to the port. By default, the flag is on.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_UNICAST_FLOOD,
                                               PROP_UNICAST_FLOOD,
                                               TRUE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               unicast_flood);

    /**
     * NMSettingBridgePort:vlan-tunnel:
     *
     * Controls whether VLAN to tunnel mapping is enabled on the port. By
     * default, the flag is off.
     *
     * Since: 1.60
     **/
    _nm_setting_property_define_direct_boolean(properties_override,
                                               obj_properties,
                                               NM_SETTING_BRIDGE_PORT_VLAN_TUNNEL,
                                               PROP_VLAN_TUNNEL,
                                               FALSE,
                                               NM_SETTING_PARAM_INFERRABLE,
                                               NMSettingBridgePortPrivate,
                                               vlan_tunnel);

    /**
     * NMSettingBridgePort:vlans: (type GPtrArray(NMBridgeVlan))
     *
     * Array of bridge VLAN objects. In addition to the VLANs
     * specified here, the port will also have the default-pvid
     * VLAN configured on the bridge by the bridge.vlan-default-pvid
     * property.
     *
     * In nmcli the VLAN list can be specified with the following
     * syntax:
     *
     *  $vid [pvid] [untagged] [, $vid [pvid] [untagged]]...
     *
     * where $vid is either a single id between 1 and 4094 or a
     * range, represented as a couple of ids separated by a dash.
     *
     * Since: 1.18
     **/
    obj_properties[PROP_VLANS] = g_param_spec_boxed(NM_SETTING_BRIDGE_PORT_VLANS,
                                                    "",
                                                    "",
                                                    G_TYPE_PTR_ARRAY,
                                                    G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE
                                                        | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_VLANS],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aa{sv}"),
                                       .compare_fcn   = compare_fcn_vlans,
                                       .to_dbus_fcn   = _nm_utils_bridge_vlans_to_dbus,
                                       .from_dbus_fcn = _nm_utils_bridge_vlans_from_dbus, ));

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_BRIDGE_PORT,
                             NULL,
                             properties_override,
                             G_STRUCT_OFFSET(NMSettingBridgePort, _priv));
}
