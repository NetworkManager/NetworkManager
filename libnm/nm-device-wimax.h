/*
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
 * Copyright 2011 - 2012 Red Hat, Inc.
 * Copyright 2009 Novell, Inc.
 */

#ifndef __NM_DEVICE_WIMAX_H__
#define __NM_DEVICE_WIMAX_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIMAX            (nm_device_wimax_get_type ())
#define NM_DEVICE_WIMAX(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIMAX, NMDeviceWimax))
#define NM_DEVICE_WIMAX_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_WIMAX, NMDeviceWimaxClass))
#define NM_IS_DEVICE_WIMAX(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIMAX))
#define NM_IS_DEVICE_WIMAX_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE_WIMAX))
#define NM_DEVICE_WIMAX_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_WIMAX, NMDeviceWimaxClass))

#define NM_DEVICE_WIMAX_HW_ADDRESS       "hw-address"
#define NM_DEVICE_WIMAX_ACTIVE_NSP       "active-nsp"
#define NM_DEVICE_WIMAX_CENTER_FREQUENCY "center-frequency"
#define NM_DEVICE_WIMAX_RSSI             "rssi"
#define NM_DEVICE_WIMAX_CINR             "cinr"
#define NM_DEVICE_WIMAX_TX_POWER         "tx-power"
#define NM_DEVICE_WIMAX_BSID             "bsid"
#define NM_DEVICE_WIMAX_NSPS             "nsps"

/**
 * NMDeviceWimax:
 */
struct _NMDeviceWimax {
	NMDevice parent;
};

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*nsp_added)   (NMDeviceWimax *self, NMWimaxNsp *nsp);
	void (*nsp_removed) (NMDeviceWimax *self, NMWimaxNsp *nsp);

	/*< private >*/
	gpointer padding[4];
} NMDeviceWimaxClass;

NM_DEPRECATED_IN_1_2
GType nm_device_wimax_get_type (void);

NM_DEPRECATED_IN_1_2
const char      *nm_device_wimax_get_hw_address  (NMDeviceWimax *wimax);
NM_DEPRECATED_IN_1_2
NMWimaxNsp      *nm_device_wimax_get_active_nsp  (NMDeviceWimax *wimax);
NM_DEPRECATED_IN_1_2
NMWimaxNsp      *nm_device_wimax_get_nsp_by_path (NMDeviceWimax *wimax,
                                                  const char *path);

NM_DEPRECATED_IN_1_2
const GPtrArray *nm_device_wimax_get_nsps        (NMDeviceWimax *wimax);

NM_DEPRECATED_IN_1_2
guint            nm_device_wimax_get_center_frequency (NMDeviceWimax *self);
NM_DEPRECATED_IN_1_2
int              nm_device_wimax_get_rssi        (NMDeviceWimax *self);
NM_DEPRECATED_IN_1_2
int              nm_device_wimax_get_cinr        (NMDeviceWimax *self);
NM_DEPRECATED_IN_1_2
int              nm_device_wimax_get_tx_power    (NMDeviceWimax *self);
NM_DEPRECATED_IN_1_2
const char *     nm_device_wimax_get_bsid        (NMDeviceWimax *self);

G_END_DECLS

#endif /* __NM_DEVICE_WIMAX_H__ */
