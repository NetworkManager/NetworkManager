/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-wimax-nsp.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_NAME, PROP_SIGNAL_QUALITY, PROP_NETWORK_TYPE, );

struct _NMWimaxNsp {
    NMObject parent;
};

struct _NMWimaxNspClass {
    NMObjectClass parent;
};

G_DEFINE_TYPE(NMWimaxNsp, nm_wimax_nsp, NM_TYPE_OBJECT)

#define NM_WIMAX_NSP_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMWimaxNsp, NM_IS_WIMAX_NSP, NMObject)

/*****************************************************************************/

/**
 * nm_wimax_nsp_get_name:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the name of the wimax NSP
 *
 * Returns: the name
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 **/
const char *
nm_wimax_nsp_get_name(NMWimaxNsp *nsp)
{
    g_return_val_if_reached(NULL);
}

/**
 * nm_wimax_nsp_get_signal_quality:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the WPA signal quality of the wimax NSP.
 *
 * Returns: the signal quality
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 **/
guint32
nm_wimax_nsp_get_signal_quality(NMWimaxNsp *nsp)
{
    g_return_val_if_reached(0);
}

/**
 * nm_wimax_nsp_get_network_type:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the network type of the wimax NSP.
 *
 * Returns: the network type
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 **/
NMWimaxNspNetworkType
nm_wimax_nsp_get_network_type(NMWimaxNsp *nsp)
{
    g_return_val_if_reached(NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN);
}

/**
 * nm_wimax_nsp_connection_valid:
 * @nsp: an #NMWimaxNsp to validate @connection against
 * @connection: an #NMConnection to validate against @nsp
 *
 * Validates a given connection against a given WiMAX NSP to ensure that the
 * connection may be activated with that NSP.  The connection must match the
 * @nsp's network name and other attributes.
 *
 * Returns: %TRUE if the connection may be activated with this WiMAX NSP,
 * %FALSE if it cannot be.
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 **/
gboolean
nm_wimax_nsp_connection_valid(NMWimaxNsp *nsp, NMConnection *connection)
{
    g_return_val_if_reached(FALSE);
}

/**
 * nm_wimax_nsp_filter_connections:
 * @nsp: an #NMWimaxNsp to filter connections for
 * @connections: (element-type NMConnection): an array of #NMConnections to
 * filter
 *
 * Filters a given array of connections for a given #NMWimaxNsp object and
 * return connections which may be activated with the NSP.  Any returned
 * connections will match the @nsp's network name and other attributes.
 *
 * Returns: (transfer full) (element-type NMConnection): an array of
 * #NMConnections that could be activated with the given @nsp.  The array should
 * be freed with g_ptr_array_unref() when it is no longer required.
 *
 * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
 **/
GPtrArray *
nm_wimax_nsp_filter_connections(NMWimaxNsp *nsp, const GPtrArray *connections)
{
    g_return_val_if_reached(NULL);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    g_return_if_reached();
}

static void
nm_wimax_nsp_init(NMWimaxNsp *nsp)
{
    g_return_if_reached();
}

static void
nm_wimax_nsp_class_init(NMWimaxNspClass *nsp_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(nsp_class);

    object_class->get_property = get_property;

    /**
     * NMWimaxNsp:name:
     *
     * The name of the WiMAX NSP.
     *
     * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
     **/
    obj_properties[PROP_NAME] = g_param_spec_string(NM_WIMAX_NSP_NAME,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMWimaxNsp:signal-quality:
     *
     * The signal quality of the WiMAX NSP.
     *
     * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
     **/
    obj_properties[PROP_SIGNAL_QUALITY] =
        g_param_spec_uint(NM_WIMAX_NSP_SIGNAL_QUALITY,
                          "",
                          "",
                          0,
                          100,
                          0,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMWimaxNsp:network-type:
     *
     * The network type of the WiMAX NSP.
     *
     * Deprecated: 1.22: WiMAX is no longer supported by NetworkManager since 1.2.0.
     **/
    obj_properties[PROP_NETWORK_TYPE] =
        g_param_spec_enum(NM_WIMAX_NSP_NETWORK_TYPE,
                          "",
                          "",
                          NM_TYPE_WIMAX_NSP_NETWORK_TYPE,
                          NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN,
                          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
