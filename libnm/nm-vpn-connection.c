/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-vpn-connection.h"

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"
#include "nm-dbus-helpers.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE(NMVpnConnection, PROP_VPN_STATE, PROP_BANNER, );

enum {
    VPN_STATE_CHANGED,

    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

typedef struct {
    char *  banner;
    guint32 vpn_state;
    guint32 reason;
} NMVpnConnectionPrivate;

struct _NMVpnConnection {
    NMActiveConnection     parent;
    NMVpnConnectionPrivate _priv;
};

struct _NMVpnConnectionClass {
    NMActiveConnectionClass parent;
};

G_DEFINE_TYPE(NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

#define NM_VPN_CONNECTION_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMVpnConnection, NM_IS_VPN_CONNECTION, NMObject, NMActiveConnection)

G_STATIC_ASSERT(sizeof(NMVpnConnectionStateReason) == sizeof(NMActiveConnectionStateReason));

/*****************************************************************************/

/**
 * nm_vpn_connection_get_banner:
 * @vpn: a #NMVpnConnection
 *
 * Gets the VPN login banner of the active #NMVpnConnection.
 *
 * Returns: the VPN login banner of the VPN connection. This is the internal
 * string used by the connection, and must not be modified.
 **/
const char *
nm_vpn_connection_get_banner(NMVpnConnection *vpn)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(vpn), NULL);

    return _nml_coerce_property_str_not_empty(NM_VPN_CONNECTION_GET_PRIVATE(vpn)->banner);
}

/**
 * nm_vpn_connection_get_vpn_state:
 * @vpn: a #NMVpnConnection
 *
 * Gets the current #NMVpnConnection state.
 *
 * Returns: the VPN state of the active VPN connection.
 **/
NMVpnConnectionState
nm_vpn_connection_get_vpn_state(NMVpnConnection *vpn)
{
    g_return_val_if_fail(NM_IS_VPN_CONNECTION(vpn), NM_VPN_CONNECTION_STATE_UNKNOWN);

    return NM_VPN_CONNECTION_GET_PRIVATE(vpn)->vpn_state;
}

/*****************************************************************************/

static void
_notify_event_state_changed(NMClient *client, NMClientNotifyEventWithPtr *notify_event)
{
    gs_unref_object NMVpnConnection *self = notify_event->user_data;
    NMVpnConnectionPrivate *         priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    /* we expose here the value cache in @priv. In practice, this is the same
     * value as we received from the signal. In the unexpected case where they
     * differ, the cached value of the current instance would still be more correct. */
    g_signal_emit(self,
                  signals[VPN_STATE_CHANGED],
                  0,
                  (guint) priv->vpn_state,
                  (guint) priv->reason);
}

void
_nm_vpn_connection_state_changed_commit(NMVpnConnection *self, guint32 state, guint32 reason)
{
    NMClient *              client;
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(self);

    client = _nm_object_get_client(self);

    if (priv->vpn_state != state) {
        priv->vpn_state = state;
        _nm_client_queue_notify_object(client, self, obj_properties[PROP_VPN_STATE]);
    }

    priv->reason = reason;

    _nm_client_notify_event_queue_with_ptr(client,
                                           NM_CLIENT_NOTIFY_EVENT_PRIO_GPROP + 1,
                                           _notify_event_state_changed,
                                           g_object_ref(self));
}

/*****************************************************************************/

static void
nm_vpn_connection_init(NMVpnConnection *connection)
{}

static void
finalize(GObject *object)
{
    NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE(object);

    g_free(priv->banner);

    G_OBJECT_CLASS(nm_vpn_connection_parent_class)->finalize(object);
}

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    NMVpnConnection *self = NM_VPN_CONNECTION(object);

    switch (prop_id) {
    case PROP_VPN_STATE:
        g_value_set_enum(value, nm_vpn_connection_get_vpn_state(self));
        break;
    case PROP_BANNER:
        g_value_set_string(value, nm_vpn_connection_get_banner(self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_vpn_connection = NML_DBUS_META_IFACE_INIT_PROP(
    NM_DBUS_INTERFACE_VPN_CONNECTION,
    nm_vpn_connection_get_type,
    NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30,
    NML_DBUS_META_IFACE_DBUS_PROPERTIES(
        NML_DBUS_META_PROPERTY_INIT_S("Banner", PROP_BANNER, NMVpnConnection, _priv.banner),
        NML_DBUS_META_PROPERTY_INIT_U("VpnState",
                                      PROP_VPN_STATE,
                                      NMVpnConnection,
                                      _priv.vpn_state), ), );

static void
nm_vpn_connection_class_init(NMVpnConnectionClass *connection_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(connection_class);

    object_class->get_property = get_property;
    object_class->finalize     = finalize;

    /**
     * NMVpnConnection:vpn-state:
     *
     * The VPN state of the active VPN connection.
     **/
    obj_properties[PROP_VPN_STATE] = g_param_spec_enum(NM_VPN_CONNECTION_VPN_STATE,
                                                       "",
                                                       "",
                                                       NM_TYPE_VPN_CONNECTION_STATE,
                                                       NM_VPN_CONNECTION_STATE_UNKNOWN,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMVpnConnection:banner:
     *
     * The VPN login banner of the active VPN connection.
     **/
    obj_properties[PROP_BANNER] = g_param_spec_string(NM_VPN_CONNECTION_BANNER,
                                                      "",
                                                      "",
                                                      NULL,
                                                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    _nml_dbus_meta_class_init_with_properties(object_class,
                                              &_nml_dbus_meta_iface_nm_vpn_connection);

    /* TODO: the state reason should also be exposed as a property in libnm's NMVpnConnection,
     * like done for NMDevice's state reason. */

    /* TODO: the D-Bus API should also expose the state-reason as a property instead of
     * a "VpnStateChanged" signal. Like done for Device's "StateReason".  */

    G_GNUC_BEGIN_IGNORE_DEPRECATIONS
    signals[VPN_STATE_CHANGED] = g_signal_new("vpn-state-changed",
                                              G_OBJECT_CLASS_TYPE(object_class),
                                              G_SIGNAL_RUN_FIRST,
                                              0,
                                              NULL,
                                              NULL,
                                              NULL,
                                              G_TYPE_NONE,
                                              2,
                                              G_TYPE_UINT,
                                              G_TYPE_UINT);
    G_GNUC_END_IGNORE_DEPRECATIONS
}
