/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-device-wimax.h"

#include "nm-wimax-nsp.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_HW_ADDRESS,
                                  PROP_ACTIVE_NSP,
                                  PROP_CENTER_FREQ,
                                  PROP_RSSI,
                                  PROP_CINR,
                                  PROP_TX_POWER,
                                  PROP_BSID,
                                  PROP_NSPS, );

enum {
    NSP_ADDED,
    NSP_REMOVED,

    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = {0};

struct _NMDeviceWimax {
    NMDevice parent;
};

struct _NMDeviceWimaxClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDeviceWimax, nm_device_wimax, NM_TYPE_DEVICE)

#define NM_DEVICE_WIMAX_GET_PRIVATE(self) \
    _NM_GET_PRIVATE(self, NMDeviceWimax, NM_IS_DEVICE_WIMAX, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_wimax_get_hw_address:
 * @wimax: a #NMDeviceWimax
 *
 * Gets the hardware (MAC) address of the #NMDeviceWimax
 *
 * Returns: the hardware address. This is the internal string used by the
 *          device, and must not be modified.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_device_wimax_get_hw_address(NMDeviceWimax *wimax)
{
    g_return_val_if_reached(NULL);
}

/**
 * nm_device_wimax_get_active_nsp:
 * @wimax: a #NMDeviceWimax
 *
 * Gets the active #NMWimaxNsp.
 *
 * Returns: (transfer full): the access point or %NULL if none is active
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMWimaxNsp *
nm_device_wimax_get_active_nsp(NMDeviceWimax *wimax)
{
    g_return_val_if_reached(NULL);
}

/**
 * nm_device_wimax_get_nsps:
 * @wimax: a #NMDeviceWimax
 *
 * Gets all the scanned NSPs of the #NMDeviceWimax.
 *
 * Returns: (element-type NMWimaxNsp): a #GPtrArray containing
 *          all the scanned #NMWimaxNsps.
 * The returned array is owned by the client and should not be modified.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const GPtrArray *
nm_device_wimax_get_nsps(NMDeviceWimax *wimax)
{
    g_return_val_if_reached(NULL);
}

/**
 * nm_device_wimax_get_nsp_by_path:
 * @wimax: a #NMDeviceWimax
 * @path: the object path of the NSP
 *
 * Gets a #NMWimaxNsp by path.
 *
 * Returns: (transfer none): the access point or %NULL if none is found.
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
NMWimaxNsp *
nm_device_wimax_get_nsp_by_path(NMDeviceWimax *wimax, const char *path)
{
    g_return_val_if_reached(NULL);
}

/**
 * nm_device_wimax_get_center_frequency:
 * @self: a #NMDeviceWimax
 *
 * Gets the center frequency (in KHz) of the radio channel the device is using
 * to communicate with the network when connected.  Has no meaning when the
 * device is not connected.
 *
 * Returns: the center frequency in KHz, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
guint
nm_device_wimax_get_center_frequency(NMDeviceWimax *self)
{
    g_return_val_if_reached(0);
}

/**
 * nm_device_wimax_get_rssi:
 * @self: a #NMDeviceWimax
 *
 * Gets the RSSI of the current radio link in dBm.  This value indicates how
 * strong the raw received RF signal from the base station is, but does not
 * indicate the overall quality of the radio link.  Has no meaning when the
 * device is not connected.
 *
 * Returns: the RSSI in dBm, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
int
nm_device_wimax_get_rssi(NMDeviceWimax *self)
{
    g_return_val_if_reached(0);
}

/**
 * nm_device_wimax_get_cinr:
 * @self: a #NMDeviceWimax
 *
 * Gets the CINR (Carrier to Interference + Noise Ratio) of the current radio
 * link in dB.  CINR is a more accurate measure of radio link quality.  Has no
 * meaning when the device is not connected.
 *
 * Returns: the CINR in dB, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
int
nm_device_wimax_get_cinr(NMDeviceWimax *self)
{
    g_return_val_if_reached(0);
}

/**
 * nm_device_wimax_get_tx_power:
 * @self: a #NMDeviceWimax
 *
 * Average power of the last burst transmitted by the device, in units of
 * 0.5 dBm.  i.e. a TxPower of -11 represents an actual device TX power of
 * -5.5 dBm.  Has no meaning when the device is not connected.
 *
 * Returns: the TX power in dBm, or 0
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
int
nm_device_wimax_get_tx_power(NMDeviceWimax *self)
{
    g_return_val_if_reached(0);
}

/**
 * nm_device_wimax_get_bsid:
 * @self: a #NMDeviceWimax
 *
 * Gets the ID of the serving Base Station when the device is connected.
 *
 * Returns: the ID of the serving Base Station, or %NULL
 *
 * Deprecated: 1.2: WiMAX is no longer supported.
 **/
const char *
nm_device_wimax_get_bsid(NMDeviceWimax *self)
{
    g_return_val_if_reached(0);
}

/*****************************************************************************/

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    g_return_if_reached();
}

static void
nm_device_wimax_init(NMDeviceWimax *device)
{
    g_return_if_reached();
}

static void
nm_device_wimax_class_init(NMDeviceWimaxClass *wimax_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(wimax_class);

    object_class->get_property = get_property;

    /**
     * NMDeviceWimax:hw-address:
     *
     * The hardware (MAC) address of the device.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_HW_ADDRESS] =
        g_param_spec_string(NM_DEVICE_WIMAX_HW_ADDRESS,
                            "",
                            "",
                            NULL,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:active-nsp:
     *
     * The active #NMWimaxNsp of the device.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_ACTIVE_NSP] =
        g_param_spec_object(NM_DEVICE_WIMAX_ACTIVE_NSP,
                            "",
                            "",
                            NM_TYPE_WIMAX_NSP,
                            G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:center-frequency:
     *
     * The center frequency (in KHz) of the radio channel the device is using to
     * communicate with the network when connected.  Has no meaning when the
     * device is not connected.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_CENTER_FREQ] = g_param_spec_uint(NM_DEVICE_WIMAX_CENTER_FREQUENCY,
                                                         "",
                                                         "",
                                                         0,
                                                         G_MAXUINT,
                                                         0,
                                                         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:rssi:
     *
     * RSSI of the current radio link in dBm.  This value indicates how strong
     * the raw received RF signal from the base station is, but does not
     * indicate the overall quality of the radio link.  Has no meaning when the
     * device is not connected.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_RSSI] = g_param_spec_int(NM_DEVICE_WIMAX_RSSI,
                                                 "",
                                                 "",
                                                 G_MININT,
                                                 G_MAXINT,
                                                 0,
                                                 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:cinr:
     *
     * CINR (Carrier to Interference + Noise Ratio) of the current radio link
     * in dB.  CINR is a more accurate measure of radio link quality.  Has no
     * meaning when the device is not connected.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_CINR] = g_param_spec_int(NM_DEVICE_WIMAX_CINR,
                                                 "",
                                                 "",
                                                 G_MININT,
                                                 G_MAXINT,
                                                 0,
                                                 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:tx-power:
     *
     * Average power of the last burst transmitted by the device, in units of
     * 0.5 dBm.  i.e. a TxPower of -11 represents an actual device TX power of
     * -5.5 dBm.  Has no meaning when the device is not connected.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_TX_POWER] = g_param_spec_int(NM_DEVICE_WIMAX_TX_POWER,
                                                     "",
                                                     "",
                                                     G_MININT,
                                                     G_MAXINT,
                                                     0,
                                                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:bsid:
     *
     * The ID of the serving base station as received from the network.  Has
     * no meaning when the device is not connected.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    obj_properties[PROP_BSID] = g_param_spec_string(NM_DEVICE_WIMAX_BSID,
                                                    "",
                                                    "",
                                                    NULL,
                                                    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    /**
     * NMDeviceWimax:nsps: (type GPtrArray(NMWimaxNsp))
     *
     * List of all WiMAX Network Service Providers the device can see.
     **/
    obj_properties[PROP_NSPS] = g_param_spec_boxed(NM_DEVICE_WIMAX_NSPS,
                                                   "",
                                                   "",
                                                   G_TYPE_PTR_ARRAY,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);

    /**
     * NMDeviceWimax::nsp-added:
     * @self: the wimax device that received the signal
     * @nsp: the new NSP
     *
     * Notifies that a #NMWimaxNsp is added to the wimax device.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    signals[NSP_ADDED] = g_signal_new("nsp-added",
                                      G_OBJECT_CLASS_TYPE(object_class),
                                      G_SIGNAL_RUN_FIRST,
                                      0,
                                      NULL,
                                      NULL,
                                      g_cclosure_marshal_VOID__OBJECT,
                                      G_TYPE_NONE,
                                      1,
                                      G_TYPE_OBJECT);

    /**
     * NMDeviceWimax::nsp-removed:
     * @self: the wimax device that received the signal
     * @nsp: the removed NSP
     *
     * Notifies that a #NMWimaxNsp is removed from the wimax device.
     *
     * Deprecated: 1.2: WiMAX is no longer supported.
     **/
    signals[NSP_REMOVED] = g_signal_new("nsp-removed",
                                        G_OBJECT_CLASS_TYPE(object_class),
                                        G_SIGNAL_RUN_FIRST,
                                        0,
                                        NULL,
                                        NULL,
                                        g_cclosure_marshal_VOID__OBJECT,
                                        G_TYPE_NONE,
                                        1,
                                        G_TYPE_OBJECT);
}
