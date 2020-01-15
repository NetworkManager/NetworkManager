// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ovs-interface.h"
#include "nm-ovsdb.h"

#include "devices/nm-device-private.h"
#include "nm-active-connection.h"
#include "nm-setting-connection.h"
#include "nm-setting-ovs-interface.h"
#include "nm-setting-ovs-port.h"

#include "devices/nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceOvsInterface);

/*****************************************************************************/

typedef struct {
	bool waiting_for_interface:1;
	int link_ifindex;
} NMDeviceOvsInterfacePrivate;

struct _NMDeviceOvsInterface {
	NMDevice parent;
	NMDeviceOvsInterfacePrivate _priv;
};

struct _NMDeviceOvsInterfaceClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceOvsInterface, nm_device_ovs_interface, NM_TYPE_DEVICE)

#define NM_DEVICE_OVS_INTERFACE_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceOvsInterface, NM_IS_DEVICE_OVS_INTERFACE, NMDevice)

/*****************************************************************************/

static const char *
get_type_description (NMDevice *device)
{
	return "ovs-interface";
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	/* The actual backing resources will be created once an interface is
	 * added to a port of ours, since there can be neither an empty port nor
	 * an empty bridge. */

	return TRUE;
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_CARRIER_DETECT | NM_DEVICE_CAP_IS_SOFTWARE;
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingOvsInterface *s_ovs_iface;

	if (!NM_DEVICE_CLASS (nm_device_ovs_interface_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_ovs_iface = nm_connection_get_setting_ovs_interface (connection);

	if (!NM_IN_STRSET (nm_setting_ovs_interface_get_interface_type (s_ovs_iface),
	                   "dpdk",
	                   "internal",
	                   "patch")) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
		                            "unsupported OVS interface type in profile");
		return FALSE;
	}

	return TRUE;
}

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (device);

	if (pllink)
		priv->link_ifindex = pllink->ifindex;

	if (   pllink
	    && priv->waiting_for_interface
	    && nm_device_get_state (device) == NM_DEVICE_STATE_IP_CONFIG) {
		priv->waiting_for_interface = FALSE;
		nm_device_bring_up (device, TRUE, NULL);
		nm_device_activate_schedule_stage3_ip_config_start (device);
	}
}

static gboolean
_is_internal_interface (NMDevice *device)
{
	NMSettingOvsInterface *s_ovs_iface;

	s_ovs_iface = nm_device_get_applied_setting (device, NM_TYPE_SETTING_OVS_INTERFACE);

	g_return_val_if_fail (s_ovs_iface, FALSE);

	return nm_streq (nm_setting_ovs_interface_get_interface_type (s_ovs_iface), "internal");
}

static NMActStageReturn
act_stage3_ip_config_start (NMDevice *device,
                            int addr_family,
                            gpointer *out_config,
                            NMDeviceStateReason *out_failure_reason)
{
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (device);

	if (!_is_internal_interface (device))
		return NM_ACT_STAGE_RETURN_IP_FAIL;

	if (nm_device_get_ip_ifindex (device) <= 0) {
		priv->waiting_for_interface = TRUE;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return NM_DEVICE_CLASS (nm_device_ovs_interface_parent_class)->act_stage3_ip_config_start (device, addr_family, out_config, out_failure_reason);
}

static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	return FALSE;
}

static void
deactivate (NMDevice *device)
{
	NMDeviceOvsInterface *self = NM_DEVICE_OVS_INTERFACE (device);
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (self);

	priv->waiting_for_interface = FALSE;
}

typedef struct {
	NMDeviceOvsInterface *self;
	GCancellable *cancellable;
	NMDeviceDeactivateCallback callback;
	gpointer callback_user_data;
	gulong link_changed_id;
	gulong cancelled_id;
} DeactivateData;

static void
deactivate_invoke_cb (DeactivateData *data, GError *error)
{
	data->callback (NM_DEVICE (data->self),
	                error,
	                data->callback_user_data);

	nm_clear_g_signal_handler (nm_device_get_platform (NM_DEVICE (data->self)),
	                           &data->link_changed_id);
	nm_clear_g_signal_handler (data->cancellable,
	                           &data->cancelled_id);
	g_object_unref (data->self);
	g_object_unref (data->cancellable);
	nm_g_slice_free (data);
}

static void
link_changed_cb (NMPlatform *platform,
                 int obj_type_i,
                 int ifindex,
                 NMPlatformLink *info,
                 int change_type_i,
                 DeactivateData *data)
{
	NMDeviceOvsInterface *self = data->self;
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (self);
	const NMPlatformSignalChangeType change_type = change_type_i;

	if (   change_type == NM_PLATFORM_SIGNAL_REMOVED
	    && ifindex == priv->link_ifindex) {
		_LOGT (LOGD_DEVICE,
		       "link %d gone, proceeding with deactivation",
		       priv->link_ifindex);
		priv->link_ifindex = 0;
		deactivate_invoke_cb (data, NULL);
		return;
	}
}

static void
deactivate_cancelled_cb (GCancellable *cancellable,
                         gpointer user_data)
{
	gs_free_error GError *error = NULL;

	nm_utils_error_set_cancelled (&error, FALSE, NULL);
	deactivate_invoke_cb ((DeactivateData *) user_data, error);
}

static void
deactivate_cb_on_idle (gpointer user_data,
                       GCancellable *cancellable)
{
	DeactivateData *data = user_data;
	gs_free_error GError *cancelled_error = NULL;

	g_cancellable_set_error_if_cancelled (data->cancellable, &cancelled_error);
	deactivate_invoke_cb (data, cancelled_error);
}

static void
deactivate_async (NMDevice *device,
                  GCancellable *cancellable,
                  NMDeviceDeactivateCallback callback,
                  gpointer callback_user_data) {

	NMDeviceOvsInterface *self = NM_DEVICE_OVS_INTERFACE (device);
	NMDeviceOvsInterfacePrivate *priv = NM_DEVICE_OVS_INTERFACE_GET_PRIVATE (self);
	DeactivateData *data;

	priv->waiting_for_interface = FALSE;

	data = g_slice_new (DeactivateData);
	*data = (DeactivateData) {
		.self = g_object_ref (self),
		.cancellable = g_object_ref (cancellable),
		.callback = callback,
		.callback_user_data = callback_user_data,
	};

	if (   !priv->link_ifindex
	    || !nm_platform_link_get (nm_device_get_platform (device), priv->link_ifindex)) {
		priv->link_ifindex = 0;
		nm_utils_invoke_on_idle (deactivate_cb_on_idle, data, cancellable);
		return;
	}

	_LOGT (LOGD_DEVICE,
	       "async deactivation: waiting for link %d to disappear",
	       priv->link_ifindex);

	data->cancelled_id = g_cancellable_connect (cancellable,
	                                            G_CALLBACK (deactivate_cancelled_cb),
	                                            data,
	                                            NULL);
	data->link_changed_id = g_signal_connect (nm_device_get_platform (device),
	                                          NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                                          G_CALLBACK (link_changed_cb),
	                                          data);
}

/*****************************************************************************/

static void
nm_device_ovs_interface_init (NMDeviceOvsInterface *self)
{
}

static const NMDBusInterfaceInfoExtended interface_info_device_ovs_interface = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DEVICE_OVS_INTERFACE,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_device_ovs_interface_class_init (NMDeviceOvsInterfaceClass *klass)
{
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_device_ovs_interface);

	device_class->connection_type_supported = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
	device_class->connection_type_check_compatible = NM_SETTING_OVS_INTERFACE_SETTING_NAME;
	device_class->link_types = NM_DEVICE_DEFINE_LINK_TYPES (NM_LINK_TYPE_OPENVSWITCH);

	device_class->deactivate = deactivate;
	device_class->deactivate_async = deactivate_async;
	device_class->get_type_description = get_type_description;
	device_class->create_and_realize = create_and_realize;
	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->is_available = is_available;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->link_changed = link_changed;
	device_class->act_stage3_ip_config_start = act_stage3_ip_config_start;
	device_class->can_unmanaged_external_down = can_unmanaged_external_down;
}
