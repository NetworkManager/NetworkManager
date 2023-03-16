/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-device-macvlan.h"

#include <linux/if_link.h>

#include "nm-device-private.h"
#include "settings/nm-settings.h"
#include "nm-act-request.h"
#include "nm-manager.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"
#include "libnm-platform/nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-macvlan.h"
#include "nm-setting-wired.h"
#include "nm-active-connection.h"
#include "nm-utils.h"

#define _NMLOG_DEVICE_TYPE NMDeviceMacvlan
#include "nm-device-logging.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMDeviceMacvlan, PROP_MODE, PROP_NO_PROMISC, PROP_TAP, );

typedef struct {
    gulong               parent_mtu_id;
    NMPlatformLnkMacvlan props;
} NMDeviceMacvlanPrivate;

struct _NMDeviceMacvlan {
    NMDevice               parent;
    NMDeviceMacvlanPrivate _priv;
};

struct _NMDeviceMacvlanClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceMacvlan, nm_device_macvlan, NM_TYPE_DEVICE)

#define NM_DEVICE_MACVLAN_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceMacvlan, NM_IS_DEVICE_MACVLAN, NMDevice)

/*****************************************************************************/

static int modes[][2] = {
    {NM_SETTING_MACVLAN_MODE_VEPA, MACVLAN_MODE_VEPA},
    {NM_SETTING_MACVLAN_MODE_BRIDGE, MACVLAN_MODE_BRIDGE},
    {NM_SETTING_MACVLAN_MODE_PRIVATE, MACVLAN_MODE_PRIVATE},
    {NM_SETTING_MACVLAN_MODE_PASSTHRU, MACVLAN_MODE_PASSTHRU},
};

static int
setting_mode_to_platform(int mode)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS(modes); i++) {
        if (modes[i][0] == mode)
            return modes[i][1];
    }

    return 0;
}

static int
platform_mode_to_setting(int mode)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS(modes); i++) {
        if (modes[i][1] == mode)
            return modes[i][0];
    }

    return 0;
}

static const char *
platform_mode_to_string(guint mode)
{
    switch (mode) {
    case MACVLAN_MODE_PRIVATE:
        return "private";
    case MACVLAN_MODE_VEPA:
        return "vepa";
    case MACVLAN_MODE_BRIDGE:
        return "bridge";
    case MACVLAN_MODE_PASSTHRU:
        return "passthru";
    default:
        return "unknown";
    }
}

/*****************************************************************************/

static void
parent_mtu_maybe_changed(NMDevice *parent, GParamSpec *pspec, gpointer user_data)
{
    /* the MTU of a macvlan/macvtap device is limited by the parent's MTU.
     *
     * When the parent's MTU changes, try to re-set the MTU. */
    nm_device_commit_mtu(user_data);
}

static void
parent_changed_notify(NMDevice *device,
                      int       old_ifindex,
                      NMDevice *old_parent,
                      int       new_ifindex,
                      NMDevice *new_parent)
{
    NMDeviceMacvlan        *self = NM_DEVICE_MACVLAN(device);
    NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE(self);

    NM_DEVICE_CLASS(nm_device_macvlan_parent_class)
        ->parent_changed_notify(device, old_ifindex, old_parent, new_ifindex, new_parent);

    nm_clear_g_signal_handler(old_parent, &priv->parent_mtu_id);

    if (new_parent) {
        priv->parent_mtu_id = g_signal_connect(new_parent,
                                               "notify::" NM_DEVICE_MTU,
                                               G_CALLBACK(parent_mtu_maybe_changed),
                                               device);
    }

    if (new_ifindex > 0) {
        /* Recheck availability now that the parent has changed */
        nm_device_queue_recheck_available(device,
                                          NM_DEVICE_STATE_REASON_PARENT_CHANGED,
                                          NM_DEVICE_STATE_REASON_PARENT_CHANGED);
    }
}

static void
update_properties(NMDevice *device)
{
    NMDeviceMacvlan            *self   = NM_DEVICE_MACVLAN(device);
    NMDeviceMacvlanPrivate     *priv   = NM_DEVICE_MACVLAN_GET_PRIVATE(self);
    GObject                    *object = G_OBJECT(device);
    const NMPlatformLnkMacvlan *props;
    const NMPlatformLink       *plink;

    if (priv->props.tap)
        props = nm_platform_link_get_lnk_macvtap(nm_device_get_platform(device),
                                                 nm_device_get_ifindex(device),
                                                 &plink);
    else
        props = nm_platform_link_get_lnk_macvlan(nm_device_get_platform(device),
                                                 nm_device_get_ifindex(device),
                                                 &plink);

    if (!props) {
        _LOGW(LOGD_PLATFORM,
              "could not get %s properties",
              priv->props.tap ? "macvtap" : "macvlan");
        return;
    }

    g_object_freeze_notify(object);

    nm_device_parent_set_ifindex(device, plink->parent);

#define CHECK_PROPERTY_CHANGED(field, prop)      \
    G_STMT_START                                 \
    {                                            \
        if (priv->props.field != props->field) { \
            priv->props.field = props->field;    \
            _notify(self, prop);                 \
        }                                        \
    }                                            \
    G_STMT_END

    CHECK_PROPERTY_CHANGED(mode, PROP_MODE);
    CHECK_PROPERTY_CHANGED(no_promisc, PROP_NO_PROMISC);

    g_object_thaw_notify(object);
}

static void
link_changed(NMDevice *device, const NMPlatformLink *pllink)
{
    NM_DEVICE_CLASS(nm_device_macvlan_parent_class)->link_changed(device, pllink);
    update_properties(device);
}

static gboolean
create_and_realize(NMDevice              *device,
                   NMConnection          *connection,
                   NMDevice              *parent,
                   const NMPlatformLink **out_plink,
                   GError               **error)
{
    const char          *iface = nm_device_get_iface(device);
    NMSettingMacvlan    *s_macvlan;
    NMPlatformLnkMacvlan lnk = {};
    int                  parent_ifindex;
    int                  r;

    s_macvlan = nm_connection_get_setting_macvlan(connection);
    g_return_val_if_fail(s_macvlan, FALSE);

    if (!parent) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
                    "MACVLAN device can not be created without a parent interface");
        return FALSE;
    }

    parent_ifindex = nm_device_get_ifindex(parent);
    if (parent_ifindex <= 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_MISSING_DEPENDENCIES,
                    "cannot retrieve ifindex of interface %s (%s)",
                    nm_device_get_iface(parent),
                    nm_device_get_type_desc(parent));
        return FALSE;
    }

    lnk.mode = setting_mode_to_platform(nm_setting_macvlan_get_mode(s_macvlan));
    if (!lnk.mode) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_FAILED,
                    "unsupported MACVLAN mode %u in connection %s",
                    nm_setting_macvlan_get_mode(s_macvlan),
                    nm_connection_get_uuid(connection));
        return FALSE;
    }
    lnk.no_promisc = !nm_setting_macvlan_get_promiscuous(s_macvlan);
    lnk.tap        = nm_setting_macvlan_get_tap(s_macvlan);

    r = nm_platform_link_macvlan_add(nm_device_get_platform(device),
                                     iface,
                                     parent_ifindex,
                                     &lnk,
                                     out_plink);
    if (r < 0) {
        g_set_error(error,
                    NM_DEVICE_ERROR,
                    NM_DEVICE_ERROR_CREATION_FAILED,
                    "Failed to create %s interface '%s' for '%s': %s",
                    lnk.tap ? "macvtap" : "macvlan",
                    iface,
                    nm_connection_get_id(connection),
                    nm_strerror(r));
        return FALSE;
    }

    return TRUE;
}

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities(NMDevice *device)
{
    /* We assume MACVLAN interfaces always support carrier detect */
    return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

/*****************************************************************************/

static gboolean
is_available(NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
    if (!nm_device_parent_get_device(device))
        return FALSE;
    return NM_DEVICE_CLASS(nm_device_macvlan_parent_class)->is_available(device, flags);
}

/*****************************************************************************/

static gboolean
check_connection_compatible(NMDevice     *device,
                            NMConnection *connection,
                            gboolean      check_properties,
                            GError      **error)
{
    NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE(device);
    NMSettingMacvlan       *s_macvlan;
    const char             *parent = NULL;

    if (!NM_DEVICE_CLASS(nm_device_macvlan_parent_class)
             ->check_connection_compatible(device, connection, check_properties, error))
        return FALSE;

    s_macvlan = nm_connection_get_setting_macvlan(connection);

    if (nm_setting_macvlan_get_tap(s_macvlan) != priv->props.tap) {
        if (priv->props.tap) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "macvtap device does not match macvlan profile");
        } else {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "macvlan device does not match macvtap profile");
        }
        return FALSE;
    }

    /* Before the device is realized some properties will not be set */
    if (check_properties && nm_device_is_real(device)) {
        if (setting_mode_to_platform(nm_setting_macvlan_get_mode(s_macvlan)) != priv->props.mode) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "macvlan mode setting differs");
            return FALSE;
        }

        if (nm_setting_macvlan_get_promiscuous(s_macvlan) == priv->props.no_promisc) {
            nm_utils_error_set_literal(error,
                                       NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                       "macvlan promiscuous setting differs");
            return FALSE;
        }

        /* Check parent interface; could be an interface name or a UUID */
        parent = nm_setting_macvlan_get_parent(s_macvlan);
        if (parent) {
            if (!nm_device_match_parent(device, parent)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "macvlan parent setting differs");
                return FALSE;
            }
        } else {
            /* Parent could be a MAC address in an NMSettingWired */
            if (!nm_device_match_parent_hwaddr(device, connection, TRUE)) {
                nm_utils_error_set_literal(error,
                                           NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
                                           "macvlan parent mac setting differs");
                return FALSE;
            }
        }
    }

    return TRUE;
}

static gboolean
complete_connection(NMDevice            *device,
                    NMConnection        *connection,
                    const char          *specific_object,
                    NMConnection *const *existing_connections,
                    GError             **error)
{
    NMSettingMacvlan *s_macvlan;

    nm_utils_complete_generic(nm_device_get_platform(device),
                              connection,
                              NM_SETTING_MACVLAN_SETTING_NAME,
                              existing_connections,
                              NULL,
                              _("MACVLAN connection"),
                              NULL,
                              NULL,
                              TRUE);

    s_macvlan = nm_connection_get_setting_macvlan(connection);
    if (!s_macvlan) {
        g_set_error_literal(error,
                            NM_DEVICE_ERROR,
                            NM_DEVICE_ERROR_INVALID_CONNECTION,
                            "A 'macvlan' setting is required.");
        return FALSE;
    }

    /* If there's no MACVLAN interface, no parent, and no hardware address in the
     * settings, then there's not enough information to complete the setting.
     */
    if (!nm_setting_macvlan_get_parent(s_macvlan)
        && !nm_device_match_parent_hwaddr(device, connection, TRUE)) {
        g_set_error_literal(
            error,
            NM_DEVICE_ERROR,
            NM_DEVICE_ERROR_INVALID_CONNECTION,
            "The 'macvlan' setting had no interface name, parent, or hardware address.");
        return FALSE;
    }

    return TRUE;
}

static void
update_connection(NMDevice *device, NMConnection *connection)
{
    NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE(device);
    NMSettingMacvlan       *s_macvlan =
        _nm_connection_ensure_setting(connection, NM_TYPE_SETTING_MACVLAN);
    int new_mode;

    new_mode = platform_mode_to_setting(priv->props.mode);
    if (new_mode != nm_setting_macvlan_get_mode(s_macvlan))
        g_object_set(s_macvlan, NM_SETTING_MACVLAN_MODE, new_mode, NULL);

    if (priv->props.no_promisc == nm_setting_macvlan_get_promiscuous(s_macvlan))
        g_object_set(s_macvlan, NM_SETTING_MACVLAN_PROMISCUOUS, !priv->props.no_promisc, NULL);

    if (priv->props.tap != nm_setting_macvlan_get_tap(s_macvlan))
        g_object_set(s_macvlan, NM_SETTING_MACVLAN_TAP, !!priv->props.tap, NULL);

    g_object_set(
        s_macvlan,
        NM_SETTING_MACVLAN_PARENT,
        nm_device_parent_find_for_connection(device, nm_setting_macvlan_get_parent(s_macvlan)),
        NULL);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_MODE:
        g_value_set_string(value, platform_mode_to_string(priv->props.mode));
        break;
    case PROP_NO_PROMISC:
        g_value_set_boolean(value, priv->props.no_promisc);
        break;
    case PROP_TAP:
        g_value_set_boolean(value, priv->props.tap);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMDeviceMacvlanPrivate *priv = NM_DEVICE_MACVLAN_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_TAP:
        priv->props.tap = g_value_get_boolean(value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    }
}

/*****************************************************************************/

static void
nm_device_macvlan_init(NMDeviceMacvlan *self)
{}

#if NM_MORE_ASSERTS
static void
dispose(GObject *object)
{
    G_OBJECT_CLASS(nm_device_macvlan_parent_class)->dispose(object);

    nm_assert(NM_DEVICE_MACVLAN_GET_PRIVATE(object)->parent_mtu_id == 0);
}
#endif

static const NMDBusInterfaceInfoExtended interface_info_device_macvlan = {
    .parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(
        NM_DBUS_INTERFACE_DEVICE_MACVLAN,
        .properties = NM_DEFINE_GDBUS_PROPERTY_INFOS(
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Parent", "o", NM_DEVICE_PARENT),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Mode", "s", NM_DEVICE_MACVLAN_MODE),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("NoPromisc",
                                                           "b",
                                                           NM_DEVICE_MACVLAN_NO_PROMISC),
            NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE("Tab", "b", NM_DEVICE_MACVLAN_TAP), ), ),
};

static void
nm_device_macvlan_class_init(NMDeviceMacvlanClass *klass)
{
    GObjectClass      *object_class      = G_OBJECT_CLASS(klass);
    NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS(klass);
    NMDeviceClass     *device_class      = NM_DEVICE_CLASS(klass);

#if NM_MORE_ASSERTS
    object_class->dispose = dispose;
#endif
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS(&interface_info_device_macvlan);

    device_class->connection_type_supported        = NM_SETTING_MACVLAN_SETTING_NAME;
    device_class->connection_type_check_compatible = NM_SETTING_MACVLAN_SETTING_NAME;
    device_class->link_types =
        NM_DEVICE_DEFINE_LINK_TYPES(NM_LINK_TYPE_MACVLAN, NM_LINK_TYPE_MACVTAP);
    device_class->mtu_parent_delta = 0;

    device_class->act_stage1_prepare_set_hwaddr_ethernet = TRUE;
    device_class->check_connection_compatible            = check_connection_compatible;
    device_class->complete_connection                    = complete_connection;
    device_class->create_and_realize                     = create_and_realize;
    device_class->get_generic_capabilities               = get_generic_capabilities;
    device_class->get_configured_mtu    = nm_device_get_configured_mtu_wired_parent;
    device_class->is_available          = is_available;
    device_class->link_changed          = link_changed;
    device_class->parent_changed_notify = parent_changed_notify;
    device_class->update_connection     = update_connection;

    obj_properties[PROP_MODE] = g_param_spec_string(NM_DEVICE_MACVLAN_MODE,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_NO_PROMISC] =
        g_param_spec_boolean(NM_DEVICE_MACVLAN_NO_PROMISC,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    obj_properties[PROP_TAP] =
        g_param_spec_boolean(NM_DEVICE_MACVLAN_TAP,
                             "",
                             "",
                             FALSE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}

/*****************************************************************************/

#define NM_TYPE_MACVLAN_DEVICE_FACTORY (nm_macvlan_device_factory_get_type())
#define NM_MACVLAN_DEVICE_FACTORY(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_MACVLAN_DEVICE_FACTORY, NMMacvlanDeviceFactory))

static NMDevice *
create_device(NMDeviceFactory      *factory,
              const char           *iface,
              const NMPlatformLink *plink,
              NMConnection         *connection,
              gboolean             *out_ignore)
{
    NMSettingMacvlan *s_macvlan;
    NMLinkType        link_type;
    gboolean          tap;

    if (connection) {
        s_macvlan = nm_connection_get_setting_macvlan(connection);
        g_assert(s_macvlan);
        tap = nm_setting_macvlan_get_tap(s_macvlan);
    } else {
        g_assert(plink);
        tap = plink->type == NM_LINK_TYPE_MACVTAP;
    }

    link_type = tap ? NM_LINK_TYPE_MACVTAP : NM_LINK_TYPE_MACVLAN;

    return g_object_new(NM_TYPE_DEVICE_MACVLAN,
                        NM_DEVICE_IFACE,
                        iface,
                        NM_DEVICE_TYPE_DESC,
                        "Macvlan",
                        NM_DEVICE_DEVICE_TYPE,
                        NM_DEVICE_TYPE_MACVLAN,
                        NM_DEVICE_LINK_TYPE,
                        link_type,
                        NM_DEVICE_MACVLAN_TAP,
                        tap,
                        NULL);
}

static const char *
get_connection_parent(NMDeviceFactory *factory, NMConnection *connection)
{
    NMSettingMacvlan *s_macvlan;
    NMSettingWired   *s_wired;
    const char       *parent = NULL;

    g_return_val_if_fail(nm_connection_is_type(connection, NM_SETTING_MACVLAN_SETTING_NAME), NULL);

    s_macvlan = nm_connection_get_setting_macvlan(connection);
    g_assert(s_macvlan);

    parent = nm_setting_macvlan_get_parent(s_macvlan);
    if (parent)
        return parent;

    /* Try the hardware address from the MACVLAN connection's hardware setting */
    s_wired = nm_connection_get_setting_wired(connection);
    if (s_wired)
        return nm_setting_wired_get_mac_address(s_wired);

    return NULL;
}

static char *
get_connection_iface(NMDeviceFactory *factory, NMConnection *connection, const char *parent_iface)
{
    NMSettingMacvlan *s_macvlan;
    const char       *ifname;

    g_return_val_if_fail(nm_connection_is_type(connection, NM_SETTING_MACVLAN_SETTING_NAME), NULL);

    s_macvlan = nm_connection_get_setting_macvlan(connection);
    g_assert(s_macvlan);

    if (!parent_iface)
        return NULL;

    ifname = nm_connection_get_interface_name(connection);
    return g_strdup(ifname);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL(
    MACVLAN,
    Macvlan,
    macvlan,
    NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(NM_LINK_TYPE_MACVLAN, NM_LINK_TYPE_MACVTAP)
        NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_MACVLAN_SETTING_NAME),
    factory_class->create_device         = create_device;
    factory_class->get_connection_parent = get_connection_parent;
    factory_class->get_connection_iface  = get_connection_iface;);
