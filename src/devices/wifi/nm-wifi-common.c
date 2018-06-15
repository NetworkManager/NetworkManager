/*-*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * (C) Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-wifi-common.h"

#include "devices/nm-device.h"
#include "nm-wifi-ap.h"
#include "nm-device-wifi.h"
#include "nm-dbus-manager.h"

#if WITH_IWD
#include "nm-device-iwd.h"
#endif

/*****************************************************************************/

void
nm_device_wifi_emit_signal_access_point (NMDevice *device,
                                         NMWifiAP *ap,
                                         gboolean is_added /* or else is_removed */)
{
	nm_dbus_object_emit_signal (NM_DBUS_OBJECT (device),
	                            &nm_interface_info_device_wireless,
	                            is_added
	                              ? &nm_signal_info_wireless_access_point_added
	                              : &nm_signal_info_wireless_access_point_removed,
	                            "(o)",
	                            nm_dbus_object_get_path (NM_DBUS_OBJECT (ap)));
}

/*****************************************************************************/

static const CList *
_dispatch_get_aps (NMDevice *device)
{
#if WITH_IWD
	if (NM_IS_DEVICE_IWD (device))
		return _nm_device_iwd_get_aps (NM_DEVICE_IWD (device));
#endif
	return _nm_device_wifi_get_aps (NM_DEVICE_WIFI (device));
}

static void
_dispatch_request_scan (NMDevice *device,
                        GVariant *options,
                        GDBusMethodInvocation *invocation)
{
#if WITH_IWD
	if (NM_IS_DEVICE_IWD (device)) {
		_nm_device_iwd_request_scan (NM_DEVICE_IWD (device),
		                             options,
		                             invocation);
		return;
	}
#endif
	_nm_device_wifi_request_scan (NM_DEVICE_WIFI (device),
	                              options,
	                              invocation);
}

static void
impl_device_wifi_get_access_points (NMDBusObject *obj,
                                    const NMDBusInterfaceInfoExtended *interface_info,
                                    const NMDBusMethodInfoExtended *method_info,
                                    GDBusConnection *connection,
                                    const char *sender,
                                    GDBusMethodInvocation *invocation,
                                    GVariant *parameters)
{
	gs_free const char **list = NULL;
	GVariant *v;
	const CList *all_aps;

	/* NOTE: this handler is called both for NMDevicwWifi and NMDeviceIwd. */

	all_aps = _dispatch_get_aps (NM_DEVICE (obj));
	list = nm_wifi_aps_get_paths (all_aps, FALSE);
	v = g_variant_new_objv (list, -1);
	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new_tuple (&v, 1));
}

static void
impl_device_wifi_get_all_access_points (NMDBusObject *obj,
                                        const NMDBusInterfaceInfoExtended *interface_info,
                                        const NMDBusMethodInfoExtended *method_info,
                                        GDBusConnection *connection,
                                        const char *sender,
                                        GDBusMethodInvocation *invocation,
                                        GVariant *parameters)
{
	gs_free const char **list = NULL;
	GVariant *v;
	const CList *all_aps;

	/* NOTE: this handler is called both for NMDevicwWifi and NMDeviceIwd. */

	all_aps = _dispatch_get_aps (NM_DEVICE (obj));
	list = nm_wifi_aps_get_paths (all_aps, TRUE);
	v = g_variant_new_objv (list, -1);
	g_dbus_method_invocation_return_value (invocation,
	                                       g_variant_new_tuple (&v, 1));
}

static void
impl_device_wifi_request_scan (NMDBusObject *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended *method_info,
                               GDBusConnection *connection,
                               const char *sender,
                               GDBusMethodInvocation *invocation,
                               GVariant *parameters)
{
	gs_unref_variant GVariant *options = NULL;

	/* NOTE: this handler is called both for NMDevicwWifi and NMDeviceIwd. */

	g_variant_get (parameters, "(@a{sv})", &options);

	_dispatch_request_scan (NM_DEVICE (obj),
	                        options,
	                        invocation);
}

const GDBusSignalInfo nm_signal_info_wireless_access_point_added = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"AccessPointAdded",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("access_point", "o"),
	),
);

const GDBusSignalInfo nm_signal_info_wireless_access_point_removed = NM_DEFINE_GDBUS_SIGNAL_INFO_INIT (
	"AccessPointRemoved",
	.args = NM_DEFINE_GDBUS_ARG_INFOS (
		NM_DEFINE_GDBUS_ARG_INFO ("access_point", "o"),
	),
);

const NMDBusInterfaceInfoExtended nm_interface_info_device_wireless = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_WIRELESS,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetAccessPoints",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("access_points", "ao"),
					),
				),
				.handle = impl_device_wifi_get_access_points,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"GetAllAccessPoints",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("access_points", "ao"),
					),
				),
				.handle = impl_device_wifi_get_all_access_points,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"RequestScan",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("options", "a{sv}"),
					),
				),
				.handle = impl_device_wifi_request_scan,
			),
		),
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
			&nm_signal_info_wireless_access_point_added,
			&nm_signal_info_wireless_access_point_removed,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("HwAddress",            "s",  NM_DEVICE_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("PermHwAddress",        "s",  NM_DEVICE_PERM_HW_ADDRESS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Mode",                 "u",  NM_DEVICE_WIFI_MODE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("BitRate",              "u",  NM_DEVICE_WIFI_BITRATE),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("AccessPoints",         "ao", NM_DEVICE_WIFI_ACCESS_POINTS),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("ActiveAccessPoint",    "o",  NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("WirelessCapabilities", "u",  NM_DEVICE_WIFI_CAPABILITIES),
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE   ("LastScan",             "x",  NM_DEVICE_WIFI_LAST_SCAN),
		),
	),
	.legacy_property_changed = TRUE,
};
