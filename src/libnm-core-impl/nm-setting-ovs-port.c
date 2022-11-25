/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-setting-ovs-port.h"

#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-ovs-port
 * @short_description: Describes connection properties for Open vSwitch ports.
 *
 * The #NMSettingOvsPort object is a #NMSetting subclass that describes properties
 * necessary for Open vSwitch ports.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMSettingOvsPort,
                             PROP_VLAN_MODE,
                             PROP_TAG,
                             PROP_TRUNKS,
                             PROP_LACP,
                             PROP_BOND_MODE,
                             PROP_BOND_UPDELAY,
                             PROP_BOND_DOWNDELAY, );

/**
 * NMSettingOvsPort:
 *
 * OvsPort Link Settings
 */
struct _NMSettingOvsPort {
    NMSetting parent;

    GPtrArray *trunks;
    char      *vlan_mode;
    char      *lacp;
    char      *bond_mode;
    guint32    tag;
    guint32    bond_updelay;
    guint32    bond_downdelay;
};

struct _NMSettingOvsPortClass {
    NMSettingClass parent;
};

G_DEFINE_TYPE(NMSettingOvsPort, nm_setting_ovs_port, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_ovs_port_get_vlan_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:vlan-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_vlan_mode(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->vlan_mode;
}

/**
 * nm_setting_ovs_port_get_tag:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:tag property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_tag(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->tag;
}

/*****************************************************************************/

/**
 * nm_setting_ovs_port_add_trunk:
 * @setting: the #NMSettingOvsPort
 * @trunk: the trunk to add
 *
 * Appends a new trunk range to the setting.
 * This takes a reference to @trunk.
 *
 * Since: 1.42
 **/
void
nm_setting_ovs_port_add_trunk(NMSettingOvsPort *self, NMRange *trunk)
{
    g_return_if_fail(NM_IS_SETTING_OVS_PORT(self));
    g_return_if_fail(trunk);

    g_ptr_array_add(self->trunks, nm_range_ref(trunk));
    _notify(self, PROP_TRUNKS);
}

/**
 * nm_setting_ovs_port_get_num_trunks:
 * @setting: the #NMSettingOvsPort
 *
 * Returns: the number of trunk ranges
 *
 * Since: 1.42
 **/
guint
nm_setting_ovs_port_get_num_trunks(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->trunks->len;
}

/**
 * nm_setting_ovs_port_get_trunk:
 * @setting: the #NMSettingOvsPort
 * @idx: index number of the trunk range to return
 *
 * Returns: (transfer none): the trunk range at index @idx
 *
 * Since: 1.42
 **/
NMRange *
nm_setting_ovs_port_get_trunk(NMSettingOvsPort *self, guint idx)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    g_return_val_if_fail(idx < self->trunks->len, NULL);

    return self->trunks->pdata[idx];
}

/**
 * nm_setting_ovs_port_remove_trunk:
 * @setting: the #NMSettingOvsPort
 * @idx: index number of the trunk range.
 *
 * Removes the trunk range at index @idx.
 *
 * Since: 1.42
 **/
void
nm_setting_ovs_port_remove_trunk(NMSettingOvsPort *self, guint idx)
{
    g_return_if_fail(NM_IS_SETTING_OVS_PORT(self));

    g_return_if_fail(idx < self->trunks->len);

    g_ptr_array_remove_index(self->trunks, idx);
    _notify(self, PROP_TRUNKS);
}

/**
 * nm_setting_ovs_port_remove_trunk_by_value:
 * @setting: the #NMSettingOvsPort
 * @start: the trunk range start index
 * @end: the trunk range end index
 *
 * Remove the trunk range with range @start to @end.
 *
 * Returns: %TRUE if the trunk range was found and removed; %FALSE otherwise
 *
 * Since: 1.42
 **/
gboolean
nm_setting_ovs_port_remove_trunk_by_value(NMSettingOvsPort *self, guint start, guint end)
{
    NMRange *trunk;
    guint    i;

    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), FALSE);

    for (i = 0; i < self->trunks->len; i++) {
        trunk = (NMRange *) self->trunks->pdata[i];
        if (trunk->start == start && trunk->end == end) {
            g_ptr_array_remove_index(self->trunks, i);
            _notify(self, PROP_TRUNKS);
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * nm_setting_ovs_port_clear_trunks:
 * @setting: the #NMSettingOvsPort
 *
 * Removes all configured trunk ranges.
 *
 * Since: 1.42
 **/
void
nm_setting_ovs_port_clear_trunks(NMSettingOvsPort *self)
{
    g_return_if_fail(NM_IS_SETTING_OVS_PORT(self));

    if (self->trunks->len != 0) {
        g_ptr_array_set_size(self->trunks, 0);
        _notify(self, PROP_TRUNKS);
    }
}

const GPtrArray *
_nm_setting_ovs_port_get_trunks_arr(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->trunks;
}

/*****************************************************************************/

/**
 * nm_setting_ovs_port_get_lacp:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:lacp property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_lacp(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->lacp;
}

/**
 * nm_setting_ovs_port_get_bond_mode:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-mode property of the setting
 *
 * Since: 1.10
 **/
const char *
nm_setting_ovs_port_get_bond_mode(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), NULL);

    return self->bond_mode;
}

/**
 * nm_setting_ovs_port_get_bond_updelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-updelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_updelay(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->bond_updelay;
}

/**
 * nm_setting_ovs_port_get_bond_downdelay:
 * @self: the #NMSettingOvsPort
 *
 * Returns: the #NMSettingOvsPort:bond-downdelay property of the setting
 *
 * Since: 1.10
 **/
guint
nm_setting_ovs_port_get_bond_downdelay(NMSettingOvsPort *self)
{
    g_return_val_if_fail(NM_IS_SETTING_OVS_PORT(self), 0);

    return self->bond_downdelay;
}

/*****************************************************************************/

static int
range_cmp(gconstpointer a, gconstpointer b)
{
    const NMRange *range_a = *(const NMRange **) a;
    const NMRange *range_b = *(const NMRange **) b;

    return nm_range_cmp(range_a, range_b);
}

gboolean
_nm_setting_ovs_port_sort_trunks(NMSettingOvsPort *self)
{
    gboolean need_sort = FALSE;
    guint    i;

    for (i = 1; i < self->trunks->len; i++) {
        NMRange *range_prev = self->trunks->pdata[i - 1];
        NMRange *range      = self->trunks->pdata[i];

        if (nm_range_cmp(range_prev, range) > 0) {
            need_sort = TRUE;
            break;
        }
    }

    if (need_sort) {
        g_ptr_array_sort(self->trunks, range_cmp);
        _notify(self, PROP_TRUNKS);
    }

    return need_sort;
}

static gboolean
verify_trunks(GPtrArray *ranges, GError **error)
{
    gs_unref_hashtable GHashTable *h = NULL;
    NMRange                       *range;
    guint                          i;
    guint                          vlan;

    if (!ranges)
        return TRUE;

    h = g_hash_table_new(nm_direct_hash, NULL);

    for (i = 0; i < ranges->len; i++) {
        range = ranges->pdata[i];
        nm_assert(range->start <= range->end);

        if (range->start > 4095 || range->end > 4095) {
            g_set_error_literal(error,
                                NM_CONNECTION_ERROR,
                                NM_CONNECTION_ERROR_INVALID_PROPERTY,
                                _("VLANs must be between 0 and 4095"));
            return FALSE;
        }

        for (vlan = range->start; vlan <= range->end; vlan++) {
            if (!nm_g_hash_table_add(h, GUINT_TO_POINTER(vlan))) {
                g_set_error(error,
                            NM_CONNECTION_ERROR,
                            NM_CONNECTION_ERROR_INVALID_PROPERTY,
                            _("duplicate VLAN %u"),
                            vlan);
                return FALSE;
            }
        }
    }

    return TRUE;
}

static gboolean
verify_trunks_normalizable(GPtrArray *ranges, GError **error)
{
    guint i;

    nm_assert(verify_trunks(ranges, NULL));

    if (!ranges || ranges->len <= 1)
        return TRUE;

    for (i = 1; i < ranges->len; i++) {
        NMRange *range_prev = ranges->pdata[i - 1];
        NMRange *range      = ranges->pdata[i];

        if (nm_range_cmp(range_prev, range) > 0) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("VLANs %u and %u are not sorted in ascending order"),
                        (guint) range_prev->start,
                        (guint) range->start);
            return FALSE;
        }
    }

    return TRUE;
}

static int
verify(NMSetting *setting, NMConnection *connection, GError **error)
{
    NMSettingOvsPort *self = NM_SETTING_OVS_PORT(setting);

    if (!_nm_connection_verify_required_interface_name(connection, error))
        return FALSE;

    if (connection) {
        NMSettingConnection *s_con;
        const char          *slave_type;

        s_con = nm_connection_get_setting_connection(connection);
        if (!s_con) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_MISSING_SETTING,
                        _("missing setting"));
            g_prefix_error(error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
            return FALSE;
        }

        if (!nm_setting_connection_get_master(s_con)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have a master."),
                        NM_SETTING_OVS_PORT_SETTING_NAME);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_MASTER);
            return FALSE;
        }

        slave_type = nm_setting_connection_get_slave_type(s_con);
        if (slave_type && strcmp(slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME)) {
            g_set_error(error,
                        NM_CONNECTION_ERROR,
                        NM_CONNECTION_ERROR_INVALID_PROPERTY,
                        _("A connection with a '%s' setting must have the slave-type set to '%s'. "
                          "Instead it is '%s'"),
                        NM_SETTING_OVS_PORT_SETTING_NAME,
                        NM_SETTING_OVS_BRIDGE_SETTING_NAME,
                        slave_type);
            g_prefix_error(error,
                           "%s.%s: ",
                           NM_SETTING_CONNECTION_SETTING_NAME,
                           NM_SETTING_CONNECTION_SLAVE_TYPE);
            return FALSE;
        }
    }

    if (!NM_IN_STRSET(self->vlan_mode,
                      "access",
                      "native-tagged",
                      "native-untagged",
                      "trunk",
                      "dot1q-tunnel",
                      NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in vlan_mode"),
                    self->vlan_mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_VLAN_MODE);
        return FALSE;
    }

    if (self->tag >= 4095) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("the tag id must be in range 0-4094 but is %u"),
                    self->tag);
        g_prefix_error(error, "%s.%s: ", NM_SETTING_OVS_PORT_SETTING_NAME, NM_SETTING_OVS_PORT_TAG);
        return FALSE;
    }

    if (!NM_IN_STRSET(self->lacp, "active", "off", "passive", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in lacp"),
                    self->lacp);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_LACP);
        return FALSE;
    }

    if (!NM_IN_STRSET(self->bond_mode, "active-backup", "balance-slb", "balance-tcp", NULL)) {
        g_set_error(error,
                    NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    _("'%s' is not allowed in bond_mode"),
                    self->bond_mode);
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_BOND_MODE);
        return FALSE;
    }

    if (!verify_trunks(self->trunks, error)) {
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_TRUNKS);
        return FALSE;
    }

    if (!verify_trunks_normalizable(self->trunks, error)) {
        g_prefix_error(error,
                       "%s.%s: ",
                       NM_SETTING_OVS_PORT_SETTING_NAME,
                       NM_SETTING_OVS_PORT_TRUNKS);
        return NM_SETTING_VERIFY_NORMALIZABLE;
    }

    return TRUE;
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMSettingOvsPort *self = NM_SETTING_OVS_PORT(object);

    switch (prop_id) {
    case PROP_TRUNKS:
        g_value_take_boxed(value,
                           _nm_utils_copy_array(self->trunks,
                                                (NMUtilsCopyFunc) nm_range_ref,
                                                (GDestroyNotify) nm_range_unref));
        break;
    default:
        _nm_setting_property_get_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMSettingOvsPort *self = NM_SETTING_OVS_PORT(object);

    switch (prop_id) {
    case PROP_TRUNKS:
        g_ptr_array_unref(self->trunks);
        self->trunks = _nm_utils_copy_array(g_value_get_boxed(value),
                                            (NMUtilsCopyFunc) nm_range_ref,
                                            (GDestroyNotify) nm_range_unref);
        break;
    default:
        _nm_setting_property_set_property_direct(object, prop_id, value, pspec);
        break;
    }
}

static void
nm_setting_ovs_port_init(NMSettingOvsPort *self)
{
    self->trunks = g_ptr_array_new_with_free_func((GDestroyNotify) nm_range_unref);
}

/**
 * nm_setting_ovs_port_new:
 *
 * Creates a new #NMSettingOvsPort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingOvsPort object
 *
 * Since: 1.10
 **/
NMSetting *
nm_setting_ovs_port_new(void)
{
    return g_object_new(NM_TYPE_SETTING_OVS_PORT, NULL);
}

static void
finalize(GObject *object)
{
    NMSettingOvsPort *self = NM_SETTING_OVS_PORT(object);

    g_ptr_array_unref(self->trunks);

    G_OBJECT_CLASS(nm_setting_ovs_port_parent_class)->finalize(object);
}

static void
nm_setting_ovs_port_class_init(NMSettingOvsPortClass *klass)
{
    GObjectClass   *object_class        = G_OBJECT_CLASS(klass);
    NMSettingClass *setting_class       = NM_SETTING_CLASS(klass);
    GArray         *properties_override = _nm_sett_info_property_override_create_array();

    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize     = finalize;

    setting_class->verify = verify;

    /**
     * NMSettingOvsPort:vlan-mode:
     *
     * The VLAN mode. One of "access", "native-tagged", "native-untagged",
     * "trunk", "dot1q-tunnel" or unset.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_VLAN_MODE,
                                              PROP_VLAN_MODE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              vlan_mode);

    /**
     * NMSettingOvsPort:tag:
     *
     * The VLAN tag in the range 0-4095.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_TAG,
                                              PROP_TAG,
                                              0,
                                              4095,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              tag);

    /**
     * NMSettingOvsPort:trunks: (type GPtrArray(NMRange))
     *
     * A list of VLAN ranges that this port trunks.
     *
     * The property is valid only for ports with mode "trunk",
     * "native-tagged", or "native-untagged port".
     * If it is empty, the port trunks all VLANs.
     *
     * Since: 1.42
     **/
    obj_properties[PROP_TRUNKS] = g_param_spec_boxed(NM_SETTING_OVS_PORT_TRUNKS,
                                                     "",
                                                     "",
                                                     G_TYPE_PTR_ARRAY,
                                                     G_PARAM_READWRITE | NM_SETTING_PARAM_INFERRABLE
                                                         | G_PARAM_STATIC_STRINGS);
    _nm_properties_override_gobj(
        properties_override,
        obj_properties[PROP_TRUNKS],
        NM_SETT_INFO_PROPERT_TYPE_DBUS(NM_G_VARIANT_TYPE("aa{sv}"),
                                       .to_dbus_fcn   = _nm_utils_ranges_to_dbus,
                                       .compare_fcn   = _nm_utils_ranges_cmp,
                                       .from_dbus_fcn = _nm_utils_ranges_from_dbus));

    /**
     * NMSettingOvsPort:lacp:
     *
     * LACP mode. One of "active", "off", or "passive".
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_LACP,
                                              PROP_LACP,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              lacp);

    /**
     * NMSettingOvsPort:bond-mode:
     *
     * Bonding mode. One of "active-backup", "balance-slb", or "balance-tcp".
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_string(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_MODE,
                                              PROP_BOND_MODE,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_mode);

    /**
     * NMSettingOvsPort:bond-updelay:
     *
     * The time port must be active before it starts forwarding traffic.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_UPDELAY,
                                              PROP_BOND_UPDELAY,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_updelay);

    /**
     * NMSettingOvsPort:bond-downdelay:
     *
     * The time port must be inactive in order to be considered down.
     *
     * Since: 1.10
     **/
    _nm_setting_property_define_direct_uint32(properties_override,
                                              obj_properties,
                                              NM_SETTING_OVS_PORT_BOND_DOWNDELAY,
                                              PROP_BOND_DOWNDELAY,
                                              0,
                                              G_MAXUINT32,
                                              0,
                                              NM_SETTING_PARAM_INFERRABLE,
                                              NMSettingOvsPort,
                                              bond_downdelay);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    _nm_setting_class_commit(setting_class,
                             NM_META_SETTING_TYPE_OVS_PORT,
                             NULL,
                             properties_override,
                             0);
}
