/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_DEVICE_WIMAX_H
#define NM_DEVICE_WIMAX_H

#include "nm-device.h"
#include "nm-wimax-nsp.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIMAX            (nm_device_wimax_get_type ())
#define NM_DEVICE_WIMAX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIMAX, NMDeviceWimax))
#define NM_DEVICE_WIMAX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WIMAX, NMDeviceWimaxClass))
#define NM_IS_DEVICE_WIMAX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIMAX))
#define NM_IS_DEVICE_WIMAX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WIMAX))
#define NM_DEVICE_WIMAX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WIMAX, NMDeviceWimaxClass))

/**
 * NMDeviceWimaxError:
 * @NM_DEVICE_WIMAX_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_WIMAX_ERROR_NOT_WIMAX_CONNECTION: the connection was not of WiMax type
 * @NM_DEVICE_WIMAX_ERROR_INVALID_WIMAX_CONNECTION: the WiMax connection was invalid
 * @NM_DEVICE_WIMAX_ERROR_INVALID_DEVICE_MAC: the device's MAC was invalid
 * @NM_DEVICE_WIMAX_ERROR_MAC_MISMATCH: the MACs of the connection and the device mismatched
 */
typedef enum {
	NM_DEVICE_WIMAX_ERROR_UNKNOWN = 0,              /*< nick=UnknownError >*/
	NM_DEVICE_WIMAX_ERROR_NOT_WIMAX_CONNECTION,     /*< nick=NotWimaxConnection >*/
	NM_DEVICE_WIMAX_ERROR_INVALID_WIMAX_CONNECTION, /*< nick=InvalidWimaxConnection >*/
	NM_DEVICE_WIMAX_ERROR_INVALID_DEVICE_MAC,       /*< nick=InvalidDeviceMac >*/
	NM_DEVICE_WIMAX_ERROR_MAC_MISMATCH,             /*< nick=MacMismatch >*/
} NMDeviceWimaxError;

#define NM_DEVICE_WIMAX_ERROR nm_device_wimax_error_quark ()
GQuark nm_device_wimax_error_quark (void);

#define NM_DEVICE_WIMAX_HW_ADDRESS       "hw-address"
#define NM_DEVICE_WIMAX_ACTIVE_NSP       "active-nsp"
#define NM_DEVICE_WIMAX_CENTER_FREQUENCY "center-frequency"
#define NM_DEVICE_WIMAX_RSSI             "rssi"
#define NM_DEVICE_WIMAX_CINR             "cinr"
#define NM_DEVICE_WIMAX_TX_POWER         "tx-power"
#define NM_DEVICE_WIMAX_BSID             "bsid"
#define NM_DEVICE_WIMAX_NSPS             "nsps"

typedef struct {
	NMDevice parent;
} NMDeviceWimax;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*nsp_added)   (NMDeviceWimax *self, NMWimaxNsp *nsp);
	void (*nsp_removed) (NMDeviceWimax *self, NMWimaxNsp *nsp);
} NMDeviceWimaxClass;

GType nm_device_wimax_get_type (void);

GObject         *nm_device_wimax_new             (DBusGConnection *connection,
												  const char *path);

const char      *nm_device_wimax_get_hw_address  (NMDeviceWimax *wimax);
NMWimaxNsp      *nm_device_wimax_get_active_nsp  (NMDeviceWimax *wimax);
NMWimaxNsp      *nm_device_wimax_get_nsp_by_path (NMDeviceWimax *wimax,
												  const char *path);

const GPtrArray *nm_device_wimax_get_nsps        (NMDeviceWimax *wimax);

guint            nm_device_wimax_get_center_frequency (NMDeviceWimax *self);
gint             nm_device_wimax_get_rssi        (NMDeviceWimax *self);
gint             nm_device_wimax_get_cinr        (NMDeviceWimax *self);
gint             nm_device_wimax_get_tx_power    (NMDeviceWimax *self);
const char *     nm_device_wimax_get_bsid        (NMDeviceWimax *self);

G_END_DECLS

#endif /* NM_DEVICE_WIMAX_H */
