/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Sjoerd Simons <sjoerd.simons@collabora.co.uk>
 * Daniel Drake <dsd@laptop.org>
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
 * (C) Copyright 2005 - 2014 Red Hat, Inc.
 * (C) Copyright 2008 Collabora Ltd.
 * (C) Copyright 2009 One Laptop per Child
 */

#include "config.h"

#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "nm-default.h"
#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-setting-connection.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-manager.h"
#include "nm-enum-types.h"
#include "nm-platform.h"
#include "nm-wifi-enum-types.h"

/* This is a bug; but we can't really change API now... */
#include "nm-vpn-dbus-interface.h"

#include "nm-device-olpc-mesh-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceOlpcMesh);

G_DEFINE_TYPE (NMDeviceOlpcMesh, nm_device_olpc_mesh, NM_TYPE_DEVICE)

#define NM_DEVICE_OLPC_MESH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshPrivate))

enum {
	PROP_0,
	PROP_COMPANION,
	PROP_ACTIVE_CHANNEL,

	LAST_PROP
};

struct _NMDeviceOlpcMeshPrivate {
	NMDevice *companion;
	gboolean  stage1_waiting;
};

/*******************************************************************/

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingOlpcMesh *s_mesh;

	if (!NM_DEVICE_CLASS (nm_device_olpc_mesh_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_OLPC_MESH_SETTING_NAME))
		return FALSE;

	s_mesh = nm_connection_get_setting_olpc_mesh (connection);
	if (!s_mesh)
		return FALSE;

	return TRUE;
}

static gboolean
can_auto_connect (NMDevice *device,
                  NMConnection *connection,
                  char **specific_object)
{
	return FALSE;
}

#define DEFAULT_SSID "olpc-mesh"

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingOlpcMesh *s_mesh;
	GByteArray *tmp;

	s_mesh = nm_connection_get_setting_olpc_mesh (connection);
	if (!s_mesh) {
		s_mesh = (NMSettingOlpcMesh *) nm_setting_olpc_mesh_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_mesh));
	}

	if (!nm_setting_olpc_mesh_get_ssid (s_mesh)) {
		tmp = g_byte_array_sized_new (strlen (DEFAULT_SSID));
		g_byte_array_append (tmp, (const guint8 *) DEFAULT_SSID, strlen (DEFAULT_SSID));
		g_object_set (G_OBJECT (s_mesh), NM_SETTING_OLPC_MESH_SSID, tmp, NULL);
		g_byte_array_free (tmp, TRUE);
	}

	if (!nm_setting_olpc_mesh_get_dhcp_anycast_address (s_mesh)) {
		const char *anycast = "c0:27:c0:27:c0:27";

		g_object_set (G_OBJECT (s_mesh), NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, anycast, NULL);

	}

	nm_utils_complete_generic (connection,
	                           NM_SETTING_OLPC_MESH_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("Mesh"),
	                           NULL,
	                           FALSE); /* No IPv6 by default */

	return TRUE;
}

/****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (device);
	NMActStageReturn ret;
	gboolean scanning;

	ret = NM_DEVICE_CLASS (nm_device_olpc_mesh_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	/* disconnect companion device, if it is connected */
	if (nm_device_get_act_request (NM_DEVICE (priv->companion))) {
		_LOGI (LOGD_OLPC, "disconnecting companion device %s",
		       nm_device_get_iface (priv->companion));
		/* FIXME: VPN stuff here is a bug; but we can't really change API now... */
		nm_device_state_changed (NM_DEVICE (priv->companion),
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
		_LOGI (LOGD_OLPC, "companion %s disconnected",
		       nm_device_get_iface (priv->companion));
	}


	/* wait with continuing configuration untill the companion device is done scanning */
	g_object_get (priv->companion, "scanning", &scanning, NULL);
	if (scanning) {
		priv->stage1_waiting = TRUE;
		return NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
_mesh_set_channel (NMDeviceOlpcMesh *self, guint32 channel)
{
	int ifindex = nm_device_get_ifindex (NM_DEVICE (self));

	if (nm_platform_mesh_get_channel (NM_PLATFORM_GET, ifindex) != channel) {
		if (nm_platform_mesh_set_channel (NM_PLATFORM_GET, ifindex, channel))
			g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL);
	}
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);
	NMConnection *connection;
	NMSettingOlpcMesh *s_mesh;
	guint32 channel;
	GBytes *ssid;
	const char *anycast_addr;

	connection = nm_device_get_connection (device);
	g_assert (connection);

	s_mesh = nm_connection_get_setting_olpc_mesh (connection);
	g_assert (s_mesh);

	channel = nm_setting_olpc_mesh_get_channel (s_mesh);
	if (channel != 0)
		_mesh_set_channel (self, channel);

	ssid = nm_setting_olpc_mesh_get_ssid (s_mesh);
	nm_platform_mesh_set_ssid (NM_PLATFORM_GET,
	                           nm_device_get_ifindex (device),
	                           g_bytes_get_data (ssid, NULL),
	                           g_bytes_get_size (ssid));

	anycast_addr = nm_setting_olpc_mesh_get_dhcp_anycast_address (s_mesh);
	nm_device_set_dhcp_anycast_address (device, anycast_addr);

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);

	if (!NM_DEVICE_OLPC_MESH_GET_PRIVATE (self)->companion) {
		_LOGD (LOGD_WIFI, "not available because companion not found");
		return FALSE;
	}

	return TRUE;
}

/*******************************************************************/

static void
companion_cleanup (NMDeviceOlpcMesh *self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	if (priv->companion) {
		g_signal_handlers_disconnect_by_data (priv->companion, self);
		g_clear_object (&priv->companion);
	}
	g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_COMPANION);
}

static void
companion_notify_cb (NMDeviceWifi *companion, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	gboolean scanning;

	if (!priv->stage1_waiting)
		return;

	g_object_get (companion, "scanning", &scanning, NULL);

	if (!scanning) {
		priv->stage1_waiting = FALSE;
		nm_device_activate_schedule_stage2_device_config (NM_DEVICE (self));
	}
}

/* disconnect from mesh if someone starts using the companion */
static void
companion_state_changed_cb (NMDeviceWifi *companion,
                            NMDeviceState state,
                            NMDeviceState old_state,
                            NMDeviceStateReason reason,
                            gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceState self_state = nm_device_get_state (NM_DEVICE (self));

	if (   self_state < NM_DEVICE_STATE_PREPARE
	    || self_state > NM_DEVICE_STATE_ACTIVATED
	    || state < NM_DEVICE_STATE_PREPARE
	    || state > NM_DEVICE_STATE_ACTIVATED)
		return;

	_LOGD (LOGD_OLPC, "disconnecting mesh due to companion connectivity");
	/* FIXME: VPN stuff here is a bug; but we can't really change API now... */
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_DISCONNECTED,
	                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
}

static gboolean
companion_scan_allowed_cb (NMDeviceWifi *companion, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceState state = nm_device_get_state (NM_DEVICE (self));

	/* Don't allow the companion to scan while configuring the mesh interface */
	return (state < NM_DEVICE_STATE_PREPARE) || (state > NM_DEVICE_STATE_IP_CONFIG);
}

static gboolean
companion_autoconnect_allowed_cb (NMDeviceWifi *companion, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceState state = nm_device_get_state (NM_DEVICE (self));

	/* Don't allow the companion to autoconnect while a mesh connection is
	 * active */
	return (state < NM_DEVICE_STATE_PREPARE) || (state > NM_DEVICE_STATE_ACTIVATED);
}

static gboolean
check_companion (NMDeviceOlpcMesh *self, NMDevice *other)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	const char *my_addr, *their_addr;

	if (!NM_IS_DEVICE_WIFI (other))
		return FALSE;

	my_addr = nm_device_get_hw_address (NM_DEVICE (self));
	their_addr = nm_device_get_hw_address (other);
	if (!nm_utils_hwaddr_matches (my_addr, -1, their_addr, -1))
		return FALSE;

	g_assert (priv->companion == NULL);
	priv->companion = g_object_ref (other);

	_LOGI (LOGD_OLPC, "found companion WiFi device %s",
	       nm_device_get_iface (other));

	g_signal_connect (G_OBJECT (other), "state-changed",
	                  G_CALLBACK (companion_state_changed_cb), self);

	g_signal_connect (G_OBJECT (other), "notify::scanning",
	                  G_CALLBACK (companion_notify_cb), self);

	g_signal_connect (G_OBJECT (other), "scanning-allowed",
	                  G_CALLBACK (companion_scan_allowed_cb), self);

	g_signal_connect (G_OBJECT (other), "autoconnect-allowed",
	                  G_CALLBACK (companion_autoconnect_allowed_cb), self);

	g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_COMPANION);

	return TRUE;
}

static void
device_added_cb (NMManager *manager, NMDevice *other, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	if (!priv->companion && check_companion (self, other)) {
		nm_device_queue_recheck_available (NM_DEVICE (self),
		                                   NM_DEVICE_STATE_REASON_NONE,
		                                   NM_DEVICE_STATE_REASON_NONE);
		nm_device_remove_pending_action (NM_DEVICE (self), "waiting for companion", TRUE);
	}
}

static void
device_removed_cb (NMManager *manager, NMDevice *other, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);

	if (other == NM_DEVICE_OLPC_MESH_GET_PRIVATE (self)->companion)
		companion_cleanup (self);
}

static void
find_companion (NMDeviceOlpcMesh *self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	const GSList *list;

	if (priv->companion)
		return;

	nm_device_add_pending_action (NM_DEVICE (self), "waiting for companion", TRUE);

	/* Try to find the companion if it's already known to the NMManager */
	for (list = nm_manager_get_devices (nm_manager_get ()); list ; list = g_slist_next (list)) {
		if (check_companion (self, NM_DEVICE (list->data))) {
			nm_device_queue_recheck_available (NM_DEVICE (self),
			                                   NM_DEVICE_STATE_REASON_NONE,
			                                   NM_DEVICE_STATE_REASON_NONE);
			nm_device_remove_pending_action (NM_DEVICE (self), "waiting for companion", TRUE);
			break;
		}
	}
}

static void
state_changed (NMDevice *device,
               NMDeviceState new_state,
               NMDeviceState old_state,
               NMDeviceStateReason reason)
{
	if (new_state == NM_DEVICE_STATE_UNAVAILABLE)
		find_companion (NM_DEVICE_OLPC_MESH (device));
}

/*******************************************************************/

NMDevice *
nm_device_olpc_mesh_new (const char *iface)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_OLPC_MESH,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "802.11 OLPC Mesh",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_OLPC_MESH,
	                                  NULL);
}

static void
nm_device_olpc_mesh_init (NMDeviceOlpcMesh * self)
{
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDeviceOlpcMesh *self;
	NMDeviceWifiCapabilities caps;

	klass = G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_OLPC_MESH (object);

	if (!nm_platform_wifi_get_capabilities (NM_PLATFORM_GET, nm_device_get_ifindex (NM_DEVICE (self)), &caps)) {
		_LOGW (LOGD_HW | LOGD_OLPC, "failed to initialize WiFi driver");
		g_object_unref (object);
		return NULL;
	}

	g_signal_connect (nm_manager_get (), "device-added", G_CALLBACK (device_added_cb), self);
	g_signal_connect (nm_manager_get (), "device-removed", G_CALLBACK (device_removed_cb), self);

	/* shorter timeout for mesh connectivity */
	nm_device_set_dhcp_timeout (NM_DEVICE (self), 20);
	return object;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceOlpcMesh *device = NM_DEVICE_OLPC_MESH (object);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (device);

	switch (prop_id) {
	case PROP_COMPANION:
		nm_utils_g_value_set_object_path (value, priv->companion);
		break;
	case PROP_ACTIVE_CHANNEL:
		g_value_set_uint (value, nm_platform_mesh_get_channel (NM_PLATFORM_GET, nm_device_get_ifindex (NM_DEVICE (device))));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (object);

	companion_cleanup (self);
	g_signal_handlers_disconnect_by_func (nm_manager_get (), G_CALLBACK (device_added_cb), self);
	g_signal_handlers_disconnect_by_func (nm_manager_get (), G_CALLBACK (device_removed_cb), self);

	G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->dispose (object);
}

static void
nm_device_olpc_mesh_class_init (NMDeviceOlpcMeshClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceOlpcMeshPrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->can_auto_connect = can_auto_connect;
	parent_class->complete_connection = complete_connection;

	parent_class->is_available = is_available;
	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;

	parent_class->state_changed = state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_COMPANION,
		 g_param_spec_boxed (NM_DEVICE_OLPC_MESH_COMPANION, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CHANNEL,
		 g_param_spec_uint (NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        &dbus_glib_nm_device_olpc_mesh_object_info);
}

