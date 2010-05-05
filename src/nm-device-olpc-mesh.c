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
 * (C) Copyright 2005 - 2010 Red Hat, Inc.
 * (C) Copyright 2008 Collabora Ltd.
 * (C) Copyright 2009 One Laptop per Child
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <netinet/in.h>
#include <string.h>
#include <net/ethernet.h>
#include <iwlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "nm-device.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-activation-request.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-olpc-mesh.h"
#include "nm-system.h"
#include "nm-manager.h"

/* This is a bug; but we can't really change API now... */
#include "NetworkManagerVPN.h"


#include "nm-device-olpc-mesh-glue.h"

static void nm_device_olpc_mesh_set_ssid (NMDeviceOlpcMesh *self, const GByteArray * ssid);

G_DEFINE_TYPE (NMDeviceOlpcMesh, nm_device_olpc_mesh, NM_TYPE_DEVICE)

#define NM_DEVICE_OLPC_MESH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_OLPC_MESH, NMDeviceOlpcMeshPrivate))


enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_COMPANION,
	PROP_ACTIVE_CHANNEL,

	LAST_PROP
};

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef enum
{
	NM_OLPC_MESH_ERROR_CONNECTION_NOT_MESH = 0,
	NM_OLPC_MESH_ERROR_CONNECTION_INVALID,
	NM_OLPC_MESH_ERROR_CONNECTION_INCOMPATIBLE,
} NMOlpcMeshError;

#define NM_OLPC_MESH_ERROR (nm_olpc_mesh_error_quark ())
#define NM_TYPE_OLPC_MESH_ERROR (nm_olpc_mesh_error_get_type ())


struct _NMDeviceOlpcMeshPrivate
{
	gboolean          dispose_has_run;

	struct ether_addr hw_addr;

	GByteArray *      ssid;

	gint8			  num_freqs;
	guint32			  freqs[IW_MAX_FREQUENCIES];

	guint8			  we_version;
	gboolean          up;

	NMDevice *        companion;
	gboolean          stage1_waiting;
	guint             device_added_id;
};

static GQuark
nm_olpc_mesh_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-mesh-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_olpc_mesh_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a wireless connection. */
			ENUM_ENTRY (NM_OLPC_MESH_ERROR_CONNECTION_NOT_MESH, "ConnectionNotMesh"),
			/* Connection was not a valid wireless connection. */
			ENUM_ENTRY (NM_OLPC_MESH_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_OLPC_MESH_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMOlpcMeshError", values);
	}
	return etype;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	int fd;
	guint32 caps = NM_DEVICE_CAP_NONE;
	struct iw_range range;
	struct iwreq wrq;
	const char *iface = nm_device_get_iface (dev);

	/* Check for Wireless Extensions support >= 16 for wireless devices */

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_OLPC_MESH, "couldn't open control socket.");
		goto out;
	}

	memset (&wrq, 0, sizeof (struct iwreq));
	memset (&range, 0, sizeof (struct iw_range));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) &range;
	wrq.u.data.length = sizeof (struct iw_range);

	if (ioctl (fd, SIOCGIWRANGE, &wrq) < 0) {
		nm_log_warn (LOGD_OLPC_MESH, "couldn't get driver range information.");
		goto out;
	}

	if ((wrq.u.data.length < 300) || (range.we_version_compiled < 16)) {
		nm_log_warn (LOGD_OLPC_MESH,
		             "(%s): driver's Wireless Extensions version (%d) is too old.",
		             iface, range.we_version_compiled);
		goto out;
	} else {
		caps |= NM_DEVICE_CAP_NM_SUPPORTED;
	}

out:
	if (fd >= 0)
		close (fd);
	return caps;
}

static void
nm_device_olpc_mesh_init (NMDeviceOlpcMesh * self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	priv->dispose_has_run = FALSE;
	priv->we_version = 0;
	priv->companion = NULL;
	priv->stage1_waiting = FALSE;

	memset (&(priv->hw_addr), 0, sizeof (struct ether_addr));
}

static guint32 iw_freq_to_uint32 (struct iw_freq *freq)
{
	if (freq->e == 0) {
		/* Some drivers report channel not frequency.  Convert to a
		 * frequency; but this assumes that the device is in b/g mode.
		 */
		if ((freq->m >= 1) && (freq->m <= 13))
			return 2407 + (5 * freq->m);
		else if (freq->m == 14)
			return 2484;
	}

	return (guint32) (((double) freq->m) * pow (10, freq->e) / 1000000);
}


/* Until a new wireless-tools comes out that has the defs and the structure,
 * need to copy them here.
 */
/* Scan capability flags - in (struct iw_range *)->scan_capa */
#define NM_IW_SCAN_CAPA_NONE  0x00
#define NM_IW_SCAN_CAPA_ESSID 0x01

struct iw_range_with_scan_capa
{
	guint32 throughput;
	guint32 min_nwid;
	guint32 max_nwid;
	guint16 old_num_channels;
	guint8  old_num_frequency;

	guint8  scan_capa;
/* don't need the rest... */
};




static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	GObjectClass *klass;
	NMDeviceOlpcMesh *self;
	NMDeviceOlpcMeshPrivate *priv;
	const char *iface;
	int fd;
	struct iw_range range;
	struct iwreq wrq;
	int i;

	klass = G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class);
	object = klass->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	self = NM_DEVICE_OLPC_MESH (object);
	priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	nm_log_dbg (LOGD_HW | LOGD_OLPC_MESH, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (self)),
	            nm_device_get_ifindex (NM_DEVICE (self)));

	iface = nm_device_get_iface (NM_DEVICE (self));
	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		goto error;

	memset (&wrq, 0, sizeof (struct iwreq));
	memset (&range, 0, sizeof (struct iw_range));
	strncpy (wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t) &range;
	wrq.u.data.length = sizeof (struct iw_range);

	if (ioctl (fd, SIOCGIWRANGE, &wrq) < 0)
		goto error;

	priv->num_freqs = MIN (range.num_frequency, IW_MAX_FREQUENCIES);
	for (i = 0; i < priv->num_freqs; i++)
		priv->freqs[i] = iw_freq_to_uint32 (&range.freq[i]);

	priv->we_version = range.we_version_compiled;

	close (fd);

	/* shorter timeout for mesh connectivity */
	nm_device_set_dhcp_timeout (NM_DEVICE (self), 20);
	return object;

error:
	if (fd >= 0)
		close (fd);
	g_object_unref (object);
	return NULL;
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_system_device_is_up (device);
}

static gboolean
real_hw_bring_up (NMDevice *dev, gboolean *no_firmware)
{
	return nm_system_device_set_up_down (dev, TRUE, no_firmware);
}

static void
real_hw_take_down (NMDevice *dev)
{
	nm_system_device_set_up_down (dev, FALSE, NULL);
}

static gboolean
real_is_up (NMDevice *device)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	return priv->up;
}

static gboolean
real_bring_up (NMDevice *dev)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (dev);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	priv->up = TRUE;
	return TRUE;
}

static void
device_cleanup (NMDeviceOlpcMesh *self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);

	if (priv->ssid) {
		g_byte_array_free (priv->ssid, TRUE);
		priv->ssid = NULL;
	}
	priv->up = FALSE;
}

static void
real_take_down (NMDevice *dev)
{
	device_cleanup (NM_DEVICE_OLPC_MESH (dev));
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMSettingConnection *s_con;
	NMSettingOlpcMesh *s_mesh;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_OLPC_MESH_SETTING_NAME)) {
		g_set_error (error,
		             NM_OLPC_MESH_ERROR, NM_OLPC_MESH_ERROR_CONNECTION_NOT_MESH,
		             "The connection was not a Mesh connection.");
		return FALSE;
	}

	s_mesh = NM_SETTING_OLPC_MESH (nm_connection_get_setting (connection, NM_TYPE_SETTING_OLPC_MESH));
	if (!s_mesh) {
		g_set_error (error,
		             NM_OLPC_MESH_ERROR, NM_OLPC_MESH_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid Mesh connection.");
		return FALSE;
	}

	return TRUE;
}

/*
 * nm_device_olpc_mesh_get_address
 *
 * Get a device's hardware address
 *
 */
static void
nm_device_olpc_mesh_get_address (NMDeviceOlpcMesh *self,
                                       struct ether_addr *addr)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	g_return_if_fail (self != NULL);
	g_return_if_fail (addr != NULL);

	memcpy (addr, &(priv->hw_addr), sizeof (struct ether_addr));
}

static int
create_socket_with_request (NMDevice *self, struct iwreq *req)
{
	int sk;
	const char * iface;

	g_return_val_if_fail (self != NULL, -1);

	sk = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sk) {
		nm_log_err (LOGD_OLPC_MESH, "Couldn't create socket: %d.", errno);
		return -1;
	}

	memset (req, 0, sizeof (struct iwreq));
	iface = nm_device_get_iface (NM_DEVICE (self));
	strncpy (req->ifr_name, iface, IFNAMSIZ);

	return sk;
}

static guint32
nm_device_olpc_mesh_get_channel (NMDeviceOlpcMesh *self)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	int sk;
	struct iwreq req;
	int ret = 0;
	int i;
	guint32 freq;

	sk = create_socket_with_request (NM_DEVICE (self), &req);
	if (sk == -1)
		return 0;

	if ((ioctl (sk, SIOCGIWFREQ, &req)) != 0) {
		nm_log_warn (LOGD_OLPC_MESH, "(%s): failed to get channel (errno: %d)",
		             nm_device_get_iface (NM_DEVICE (self)), errno);
		goto out;
	}

	freq = iw_freq_to_uint32 (&req.u.freq);

	for (i = 0 ; i < priv->num_freqs; i++) {
		if (freq == priv->freqs[i])
			break;
	}
	if (i < priv->num_freqs)
		ret = i + 1;

out:
	if (sk >= 0)
		close (sk);
	return ret;
}

static void
nm_device_olpc_mesh_set_channel (NMDeviceOlpcMesh *self, guint32 channel)
{
	int sk;
	struct iwreq req;

	if (nm_device_olpc_mesh_get_channel (self) == channel)
		return;

	sk = create_socket_with_request (NM_DEVICE (self), &req);
	if (sk < 0)
		return;

	if (channel > 0) {
		req.u.freq.flags = IW_FREQ_FIXED;
		req.u.freq.e = 0;
		req.u.freq.m = channel;
	}

	if (ioctl (sk, SIOCSIWFREQ, &req) != 0) {
		nm_log_warn (LOGD_OLPC_MESH, "(%s): failed to set to channel %d (errno: %d)",
		             nm_device_get_iface (NM_DEVICE (self)), channel, errno);
	} else
		g_object_notify (G_OBJECT (self), NM_DEVICE_OLPC_MESH_ACTIVE_CHANNEL);

	close (sk);
}

static void
nm_device_olpc_mesh_set_ssid (NMDeviceOlpcMesh *self, const GByteArray * ssid)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	int sk;
	struct iwreq wrq;
	const char * iface;
	guint32 len = 0;
	char buf[IW_ESSID_MAX_SIZE + 1];

	g_return_if_fail (self != NULL);

	sk = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sk) {
		nm_log_err (LOGD_OLPC_MESH, "Couldn't create socket: %d.", errno);
		return;
	}

	iface = nm_device_get_iface (NM_DEVICE (self));

	memset (buf, 0, sizeof (buf));
	if (ssid) {
		len = ssid->len;
		memcpy (buf, ssid->data, MIN (sizeof (buf) - 1, len));
	}
	wrq.u.essid.pointer = (caddr_t) buf;

	if (priv->we_version < 21) {
		/* For historic reasons, set SSID length to include one extra
		 * character, C string nul termination, even though SSID is
		 * really an octet string that should not be presented as a C
		 * string. Some Linux drivers decrement the length by one and
		 * can thus end up missing the last octet of the SSID if the
		 * length is not incremented here. WE-21 changes this to
		 * explicitly require the length _not_ to include nul
		 * termination. */
		if (len)
			len++;
	}
	wrq.u.essid.length = len;
	wrq.u.essid.flags = (len > 0) ? 1 : 0; /* 1=enable SSID, 0=disable/any */

	strncpy (wrq.ifr_name, iface, IFNAMSIZ);

	if (ioctl (sk, SIOCSIWESSID, &wrq) < 0) {
		if (errno != ENODEV) {
			nm_log_err (LOGD_OLPC_MESH, "(%s): error setting SSID to '%s': %s",
			            iface,
			            ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(null)",
			            strerror (errno));
		}
    }

	close (sk);
}

/****************************************************************************/

static void
real_update_hw_address (NMDevice *dev)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (dev);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	struct ifreq req;
	int ret, fd;

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		nm_log_warn (LOGD_OLPC_MESH, "could not open control socket.");
		return;
	}

	memset (&req, 0, sizeof (struct ifreq));
	strncpy (req.ifr_name, nm_device_get_iface (dev), IFNAMSIZ);
	ret = ioctl (fd, SIOCGIFHWADDR, &req);
	if (ret) {
		nm_log_warn (LOGD_OLPC_MESH, "(%s): error getting hardware address: %d",
		             nm_device_get_iface (dev), errno);
		goto out;
	}

	if (memcmp (&priv->hw_addr, &req.ifr_hwaddr.sa_data, sizeof (struct ether_addr))) {
		memcpy (&priv->hw_addr, &req.ifr_hwaddr.sa_data, sizeof (struct ether_addr));
		g_object_notify (G_OBJECT (dev), NM_DEVICE_OLPC_MESH_HW_ADDRESS);
	}

out:
	close (fd);
}


static NMActStageReturn
real_act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
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

static NMActStageReturn
real_act_stage2_config (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (dev);
	NMConnection *connection;
	NMSettingOlpcMesh *s_mesh;
	NMActRequest *req;
	guint32 channel;
	const GByteArray *anycast_addr_array;
	guint8 *anycast_addr = NULL;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_mesh = NM_SETTING_OLPC_MESH (nm_connection_get_setting (connection, NM_TYPE_SETTING_OLPC_MESH));
	g_assert (s_mesh);

	channel = nm_setting_olpc_mesh_get_channel (s_mesh);
	if (channel != 0)
		nm_device_olpc_mesh_set_channel (self, channel);
	nm_device_olpc_mesh_set_ssid (self, nm_setting_olpc_mesh_get_ssid (s_mesh));

	anycast_addr_array = nm_setting_olpc_mesh_get_dhcp_anycast_address (s_mesh);
	if (anycast_addr_array)
		anycast_addr = anycast_addr_array->data;

	nm_device_set_dhcp_anycast_address (dev, anycast_addr);
	return NM_ACT_STAGE_RETURN_SUCCESS;
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

	device_cleanup (self);

	manager = nm_manager_get (NULL, NULL, NULL, FALSE, FALSE, FALSE, NULL);
	if (priv->device_added_id)
		g_signal_handler_disconnect (manager, priv->device_added_id);
	g_object_unref (manager);

	G_OBJECT_CLASS (nm_device_olpc_mesh_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceOlpcMesh *device = NM_DEVICE_OLPC_MESH (object);
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (device);
	struct ether_addr hw_addr;

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		nm_device_olpc_mesh_get_address (device, &hw_addr);
		g_value_take_string (value, nm_ether_ntop (&hw_addr));
		break;
	case PROP_COMPANION:
		if (priv->companion)
			g_value_set_boxed (value, nm_device_get_path (priv->companion));
		else
			g_value_set_boxed (value, "/");
		break;
	case PROP_ACTIVE_CHANNEL:
		g_value_set_uint (value, nm_device_olpc_mesh_get_channel (device));
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

	parent_class->get_type_capabilities = NULL;
	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->hw_is_up = real_hw_is_up;
	parent_class->hw_bring_up = real_hw_bring_up;
	parent_class->hw_take_down = real_hw_take_down;
	parent_class->is_up = real_is_up;
	parent_class->bring_up = real_bring_up;
	parent_class->take_down = real_take_down;
	parent_class->update_hw_address = real_update_hw_address;
	parent_class->check_connection_compatible = real_check_connection_compatible;

	parent_class->act_stage1_prepare = real_act_stage1_prepare;
	parent_class->act_stage2_config = real_act_stage2_config;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_OLPC_MESH_HW_ADDRESS,
		                      "MAC Address",
		                      "Hardware MAC address",
		                      NULL,
		                      G_PARAM_READABLE));

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

	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceOlpcMeshClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass), &dbus_glib_nm_device_olpc_mesh_object_info);

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
	NMDeviceState state;

	g_object_get (G_OBJECT (self), NM_DEVICE_INTERFACE_STATE, &state, NULL);

	/* Don't allow the companion to scan while configure the mesh interface */
	return (state < NM_DEVICE_STATE_PREPARE) || (state > NM_DEVICE_STATE_IP_CONFIG);
}

static gboolean
companion_autoconnect_allowed_cb (NMDeviceWifi *companion, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (user_data);
	NMDeviceState state;

	g_object_get (G_OBJECT (self), NM_DEVICE_INTERFACE_STATE, &state, NULL);

	/* Don't allow the companion to autoconnect while a mesh connection is
	 * active */
	return (state < NM_DEVICE_STATE_PREPARE) || (state > NM_DEVICE_STATE_ACTIVATED);
}

static gboolean
is_companion (NMDeviceOlpcMesh *self, NMDevice *other)
{
	NMDeviceOlpcMeshPrivate *priv = NM_DEVICE_OLPC_MESH_GET_PRIVATE (self);
	struct ether_addr their_addr;
	NMManager *manager;

	if (!NM_IS_DEVICE_WIFI (other))
		return FALSE;

	nm_device_wifi_get_address (NM_DEVICE_WIFI (other), &their_addr);

	if (memcmp (priv->hw_addr.ether_addr_octet,
		their_addr.ether_addr_octet, ETH_ALEN) != 0) {
		return FALSE;
	}

	/* FIXME detect when our companion leaves */
	priv->companion = other;

	/* When we've found the companion, stop listening for other devices */
	manager = nm_manager_get (NULL, NULL, NULL, FALSE, FALSE, FALSE, NULL);
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

	is_companion (self, other);
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

	manager = nm_manager_get (NULL, NULL, NULL, FALSE, FALSE, FALSE, NULL);

	priv->device_added_id = g_signal_connect (manager, "device-added",
	                                          G_CALLBACK (device_added_cb), self);

	/* Try to find the companion if it's already known to the NMManager */
	for (list = nm_manager_get_devices (manager); list ; list = g_slist_next (list)) {
		if (is_companion (self, NM_DEVICE (list->data)))
			break;
	}

	g_object_unref (manager);

	return FALSE;
}

static void
state_changed_cb (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMDeviceOlpcMesh *self = NM_DEVICE_OLPC_MESH (device);

	switch (state) {
	case NM_DEVICE_STATE_UNMANAGED:
		break;
	case NM_DEVICE_STATE_UNAVAILABLE:
		/* If transitioning to UNAVAILBLE and the companion device is known then
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
nm_device_olpc_mesh_new (const char *udi,
                         const char *iface,
                         const char *driver)
{
	GObject *obj;

	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	obj = g_object_new (NM_TYPE_DEVICE_OLPC_MESH,
	                    NM_DEVICE_INTERFACE_UDI, udi,
	                    NM_DEVICE_INTERFACE_IFACE, iface,
	                    NM_DEVICE_INTERFACE_DRIVER, driver,
	                    NM_DEVICE_INTERFACE_TYPE_DESC, "802.11 OLPC Mesh",
	                    NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_OLPC_MESH,
	                    NULL);
	if (obj == NULL)
		return NULL;

	g_signal_connect (obj, "state-changed", G_CALLBACK (state_changed_cb), NULL);

	return NM_DEVICE (obj);
}
