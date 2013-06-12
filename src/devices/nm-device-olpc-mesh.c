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
 * (C) Copyright 2005 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Collabora Ltd.
 * (C) Copyright 2009 One Laptop per Child
 */

#include "config.h"
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-setting-connection.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-system.h"
#include "nm-manager.h"
#include "nm-enum-types.h"
#include "nm-dbus-manager.h"
#include "wifi-utils.h"
#if HAVE_WEXT
#include "wifi-utils-wext.h"
#endif

/* This is a bug; but we can't really change API now... */
#include "NetworkManagerVPN.h"


#include "nm-device-olpc-mesh-glue.h"

G_DEFINE_TYPE (NMDeviceOlpcMesh, nm_device_olpc_mesh, NM_TYPE_DEVICE)

#define NM_DEVICE_OLPC_MESH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshPrivate))


enum {
	PROP_0,
	PROP_COMPANION,
	PROP_ACTIVE_CHANNEL,

	LAST_PROP
};

#define NM_OLPC_MESH_ERROR (nm_olpc_mesh_error_quark ())


struct _NMDeviceOlpcMeshPrivate {
	gboolean          dispose_has_run;

	WifiData *        wifi_data;

	NMDevice *        companion;
	gboolean          stage1_waiting;
	guint             device_added_id;
	guint             device_removed_id;
	guint             cmp_state_changed_id;
	guint             cmp_scanning_id;
	guint             cmp_scanning_allowed_id;
	guint             cmp_autoconnect_allowed_id;
};

static void state_changed (NMDevice *device, NMDeviceState new_state,
                           NMDeviceState old_state, NMDeviceStateReason reason);

static GQuark
nm_olpc_mesh_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-mesh-error");
	return quark;
}

static void
nm_device_olpc_mesh_init (NMDeviceOlpcMesh * self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	priv->dispose_has_run = FALSE;
	priv->companion = NULL;
	priv->stage1_waiting = FALSE;
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDeviceOlpcMesh *self;
	NMDeviceOlpcMeshPrivate *priv;

	klass = G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_OLPC_MESH (object);
	priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | LOGD_OLPC_MESH, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	/*
	 * The kernel driver now uses nl80211, but we force use of WEXT because
	 * the cfg80211 interactions are not quite ready to support access to
	 * mesh control through nl80211 just yet.
	 */
#if HAVE_WEXT
	priv->wifi_data = wifi_wext_init (nm_device_get_iface (NM_DEVICE (self)),
	                                  nm_device_get_ifindex (NM_DEVICE (self)),
	                                  FALSE);
#endif
	if (priv->wifi_data == NULL) {
		nm_log_warn (LOGD_HW | LOGD_OLPC_MESH, "(%s): failed to initialize WiFi driver",
		             nm_device_get_iface (NM_DEVICE (self)));
		g_object_unref (object);
		return NULL;
	}

	/* shorter timeout for mesh connectivity */
	nm_device_set_dhcp_timeout (NM_DEVICE (self), 20);
	return object;
}

static gboolean
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMSettingConnection *s_con;
	NMSettingOlpcMesh *s_mesh;

	if (!NM_DEVICE_CLASS (nm_device_olpc_mesh_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		g_set_error (error,
		             NM_OLPC_MESH_ERROR, NM_OLPC_MESH_ERROR_CONNECTION_NOT_MESH,
		             "The connection was not a Mesh connection.");
		return FALSE;
	}

	s_mesh = nm_connection_get_setting_olpc_mesh (connection);
	if (!s_mesh) {
		g_set_error (error,
		             NM_OLPC_MESH_ERROR, NM_OLPC_MESH_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid Mesh connection.");
		return FALSE;
	}

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
		const guint8 anycast[ETH_ALEN] = { 0xC0, 0x27, 0xC0, 0x27, 0xC0, 0x27 };

		tmp = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (tmp, anycast, sizeof (anycast));
		g_object_set (G_OBJECT (s_mesh), NM_SETTING_OLPC_MESH_DHCP_ANYCAST_ADDRESS, tmp, NULL);
		g_byte_array_free (tmp, TRUE);

	}

	nm_utils_complete_generic (connection,
	                           NM_SETTING_OLPC_MESH_SETTING_NAME,
	                           existing_connections,
	                           _("Mesh %d"),
	                           NULL,
	                           FALSE); /* No IPv6 by default */

	return TRUE;
}

/****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (dev);
	gboolean scanning;

	/* disconnect companion device, if it is connected */
	if (nm_device_get_act_request (NM_DEVICE (priv->companion))) {
		nm_log_info (LOGD_OLPC_MESH, "(%s): disconnecting companion device %s",
		             nm_device_get_iface (dev),
		             nm_device_get_iface (priv->companion));
		/* FIXME: VPN stuff here is a bug; but we can't really change API now... */
		nm_device_state_changed (NM_DEVICE (priv->companion),
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);
		nm_log_info (LOGD_OLPC_MESH, "(%s): companion %s disconnected",
		             nm_device_get_iface (dev),
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
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	if (wifi_utils_get_mesh_channel (priv->wifi_data) != channel) {
		if (wifi_utils_set_mesh_channel (priv->wifi_data, channel))
			g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL);
	}
}

static NMActStageReturn
act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (dev);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingOlpcMesh *s_mesh;
	guint32 channel;
	const GByteArray *anycast_addr_array;
	guint8 *anycast_addr = NULL;

	connection = nm_device_get_connection (dev);
	g_assert (connection);

	s_mesh = nm_connection_get_setting_olpc_mesh (connection);
	g_assert (s_mesh);

	channel = nm_setting_olpc_mesh_get_channel (s_mesh);
	if (channel != 0)
		_mesh_set_channel (self, channel);
	wifi_utils_set_mesh_ssid (priv->wifi_data, nm_setting_olpc_mesh_get_ssid (s_mesh));

	anycast_addr_array = nm_setting_olpc_mesh_get_dhcp_anycast_address (s_mesh);
	if (anycast_addr_array)
		anycast_addr = anycast_addr_array->data;

	nm_device_set_dhcp_anycast_address (dev, anycast_addr);
	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
companion_cleanup (NMDeviceOlpcMesh *self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	if (priv->companion == NULL)
		return;

	if (priv->cmp_state_changed_id) {
		g_signal_handler_disconnect (priv->companion, priv->cmp_state_changed_id);
		priv->cmp_state_changed_id = 0;
	}

	if (priv->cmp_scanning_id) {
		g_signal_handler_disconnect (priv->companion, priv->cmp_scanning_id);
		priv->cmp_scanning_id = 0;
	}

	if (priv->cmp_scanning_allowed_id) {
		g_signal_handler_disconnect (priv->companion, priv->cmp_scanning_allowed_id);
		priv->cmp_scanning_allowed_id = 0;
	}

	if (priv->cmp_autoconnect_allowed_id) {
		g_signal_handler_disconnect (priv->companion, priv->cmp_autoconnect_allowed_id);
		priv->cmp_autoconnect_allowed_id = 0;
	}

	priv->companion = NULL;
	g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_COMPANION);
}

static void
dispose (GObject *object)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (object);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	NMManager *manager;

	if (priv->dispose_has_run) {
		G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->dispose (object);
		return;
	}
	priv->dispose_has_run = TRUE;

	if (priv->wifi_data)
		wifi_utils_deinit (priv->wifi_data);

	companion_cleanup (self);

	manager = nm_manager_get ();
	if (priv->device_added_id)
		g_signal_handler_disconnect (manager, priv->device_added_id);
	if (priv->device_removed_id)
		g_signal_handler_disconnect (manager, priv->device_removed_id);
	g_object_unref (manager);

	G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceOlpcMesh *device = NM_DEVICE_OLPC_MESH (object);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (device);

	switch (prop_id) {
	case PROP_COMPANION:
		if (priv->companion)
			g_value_set_boxed (value, nm_device_get_path (priv->companion));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_ACTIVE_CHANNEL:
		g_value_set_uint (value, wifi_utils_get_mesh_channel (priv->wifi_data));
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

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;

	parent_class->state_changed = state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_COMPANION,
		 g_param_spec_boxed (NM_DEVICE_OLPC_MESH_COMPANION,
		                     "Companion device",
		                     "Companion device object path",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CHANNEL,
		 g_param_spec_uint (NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL,
		                   "Active channel",
		                   "Active channel",
		                   0, G_MAXUINT32, 0,
		                   G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_olpc_mesh_object_info);

	dbus_g_error_domain_register (NM_OLPC_MESH_ERROR, NULL, 
	                              NM_TYPE_OLPC_MESH_ERROR);
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

	nm_log_dbg (LOGD_OLPC_MESH, "(%s): disconnecting mesh due to companion connectivity",
	            nm_device_get_iface (NM_DEVICE (self)));
	/* FIXME: VPN stuff here is a bug; but we can't really change API now... */
	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_DISCONNECTED,
	                         NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);
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
is_companion (NMDeviceOlpcMesh *self, NMDevice *other)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	const guint8 *my_addr, *their_addr;
	guint their_addr_len;
	NMManager *manager;

	if (!NM_IS_DEVICE_WIFI (other))
		return FALSE;

	my_addr = nm_device_get_hw_address (NM_DEVICE (self), NULL);
	their_addr = nm_device_get_hw_address (other, &their_addr_len);
	if (   (their_addr_len != ETH_ALEN)
	    || (memcmp (my_addr, their_addr, ETH_ALEN) != 0))
		return FALSE;

	priv->companion = other;

	/* When we've found the companion, stop listening for other devices */
	manager = nm_manager_get ();
	if (priv->device_added_id) {
		g_signal_handler_disconnect (manager, priv->device_added_id);
		priv->device_added_id = 0;
	}
	g_object_unref (manager);

	nm_device_state_changed (NM_DEVICE (self),
	                         NM_DEVICE_STATE_DISCONNECTED,
	                         NM_DEVICE_STATE_REASON_NONE);

	nm_log_info (LOGD_OLPC_MESH, "(%s): found companion WiFi device %s",
	             nm_device_get_iface (NM_DEVICE (self)),
	             nm_device_get_iface (other));

	priv->cmp_state_changed_id = g_signal_connect (G_OBJECT (other), "state-changed",
	                                               G_CALLBACK (companion_state_changed_cb), self);

	priv->cmp_scanning_id = g_signal_connect (G_OBJECT (other), "notify::scanning",
	                                          G_CALLBACK (companion_notify_cb), self);

	priv->cmp_scanning_allowed_id = g_signal_connect (G_OBJECT (other), "scanning-allowed",
	                                                  G_CALLBACK (companion_scan_allowed_cb), self);

	priv->cmp_autoconnect_allowed_id = g_signal_connect (G_OBJECT (other), "autoconnect-allowed",
	                                                     G_CALLBACK (companion_autoconnect_allowed_cb), self);

	g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_COMPANION);

	return TRUE;
}

static void
device_added_cb (NMManager *manager, NMDevice *other, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);

	is_companion (self, other);
}

static void
device_removed_cb (NMManager *manager, NMDevice *other, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);

	if (other == NM_DEVICE_OLPC_MESH_GET_PRIVATE (self)->companion)
		companion_cleanup (self);
}

static gboolean
check_companion_cb (gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	NMManager *manager;
	GSList *list;

	if (priv->companion != NULL) {
		nm_device_state_changed (NM_DEVICE (user_data),
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_NONE);
		return FALSE;
	}

	if (priv->device_added_id != 0)
		return FALSE;

	manager = nm_manager_get ();

	priv->device_added_id = g_signal_connect (manager, "device-added",
	                                          G_CALLBACK (device_added_cb), self);
	if (!priv->device_removed_id) {
		priv->device_removed_id = g_signal_connect (manager, "device-removed",
	                                                G_CALLBACK (device_removed_cb), self);
	}

	/* Try to find the companion if it's already known to the NMManager */
	for (list = nm_manager_get_devices (manager); list ; list = g_slist_next (list)) {
		if (is_companion (self, NM_DEVICE (list->data)))
			break;
	}

	g_object_unref (manager);

	return FALSE;
}

static void
state_changed (NMDevice *device, NMDeviceState new_state,
               NMDeviceState old_state, NMDeviceStateReason reason)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If transitioning to UNAVAILABLE and the companion device is known then
		 * transition to DISCONNECTED otherwise wait for our companion.
		 */
		g_idle_add (check_companion_cb, self);
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	case NM_DEVICE_STATE_FAILED:
		break;
	case NM_DEVICE_STATE_DISCONNECTED:
		break;
	default:
		break;
	}
}


NMDevice *
nm_device_olpc_mesh_new (NMPlatformLink *platform_device)
{
	g_return_val_if_fail (platform_device != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_OLPC_MESH,
	                                  NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                  NM_DEVICE_TYPE_DESC, "802.11 OLPC Mesh",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_OLPC_MESH,
	                                  NULL);
}
