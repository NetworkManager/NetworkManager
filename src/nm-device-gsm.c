/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include <string.h>

#include "nm-modem-gsm.h"
#include "nm-device-interface.h"
#include "nm-device-gsm.h"
#include "nm-properties-changed-signal.h"
#include "nm-rfkill.h"

#include "nm-device-gsm-glue.h"

G_DEFINE_TYPE (NMDeviceGsm, nm_device_gsm, NM_TYPE_DEVICE_MODEM)

enum {
	PROPERTIES_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

NMDevice *
nm_device_gsm_new (NMModemGsm *modem, const char *driver)
{
	g_return_val_if_fail (modem != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM_GSM (modem), NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_GSM,
	                                  NM_DEVICE_INTERFACE_UDI, nm_modem_get_path (NM_MODEM (modem)),
	                                  NM_DEVICE_INTERFACE_IFACE, nm_modem_get_iface (NM_MODEM (modem)),
	                                  NM_DEVICE_INTERFACE_DRIVER, driver,
	                                  NM_DEVICE_INTERFACE_TYPE_DESC, "GSM",
	                                  NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_GSM,
	                                  NM_DEVICE_INTERFACE_RFKILL_TYPE, RFKILL_TYPE_WWAN,
	                                  NM_DEVICE_MODEM_MODEM, modem,
	                                  NULL);
}

static void
nm_device_gsm_init (NMDeviceGsm *self)
{
}

static void
nm_device_gsm_class_init (NMDeviceGsmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	/* Signals */
	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceGsmClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_gsm_object_info);
}

