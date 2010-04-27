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

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "wireless-helper.h"

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include "nm-udev-manager.h"
#include "nm-marshal.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-ethernet.h"

typedef struct {
	GUdevClient *client;

	/* Authoritative rfkill state (RFKILL_* enum) */
	RfKillState rfkill_states[RFKILL_TYPE_MAX];
	GSList *killswitches;

	gboolean disposed;
} NMUdevManagerPrivate;

#define NM_UDEV_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_UDEV_MANAGER, NMUdevManagerPrivate))

G_DEFINE_TYPE (NMUdevManager, nm_udev_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	RFKILL_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


typedef struct {
	char *name;
	guint64 seqnum;
	char *path;
	char *driver;
	RfKillType rtype;
	gint state;
} Killswitch;

RfKillState
nm_udev_manager_get_rfkill_state (NMUdevManager *self, RfKillType rtype)
{
	g_return_val_if_fail (self != NULL, RFKILL_UNBLOCKED);
	g_return_val_if_fail (rtype < RFKILL_TYPE_MAX, RFKILL_UNBLOCKED);

	return NM_UDEV_MANAGER_GET_PRIVATE (self)->rfkill_states[rtype];
}

static const char *
rfkill_type_to_desc (RfKillType rtype)
{
	if (rtype == 0)
		return "WiFi";
	else if (rtype == 1)
		return "WWan";
	else if (rtype == 2)
		return "WiMAX";
	return "unknown";
}

static const char *
rfkill_state_to_desc (RfKillState rstate)
{
	if (rstate == 0)
		return "unblocked";
	else if (rstate == 1)
		return "soft-blocked";
	else if (rstate == 2)
		return "hard-blocked";
	return "unknown";
}

static Killswitch *
killswitch_new (GUdevDevice *device, RfKillType rtype)
{
	Killswitch *ks;
	GUdevDevice *parent = NULL;
	const char *driver;

	ks = g_malloc0 (sizeof (Killswitch));
	ks->name = g_strdup (g_udev_device_get_name (device));
	ks->seqnum = g_udev_device_get_seqnum (device);
	ks->path = g_strdup (g_udev_device_get_sysfs_path (device));
	ks->rtype = rtype;

	driver = g_udev_device_get_property (device, "DRIVER");
	if (!driver) {
		parent = g_udev_device_get_parent (device);
		if (parent)
			driver = g_udev_device_get_property (parent, "DRIVER");
	}
	if (driver)
		ks->driver = g_strdup (driver);

	if (parent)
		g_object_unref (parent);

	return ks;
}

static void
killswitch_destroy (Killswitch *ks)
{
	g_return_if_fail (ks != NULL);

	g_free (ks->name);
	g_free (ks->path);
	g_free (ks->driver);
	memset (ks, 0, sizeof (Killswitch));
	g_free (ks);
}

NMUdevManager *
nm_udev_manager_new (void)
{
	return NM_UDEV_MANAGER (g_object_new (NM_TYPE_UDEV_MANAGER, NULL));
}

static RfKillState
sysfs_state_to_nm_state (gint sysfs_state)
{
	switch (sysfs_state) {
	case 0:
		return RFKILL_SOFT_BLOCKED;
	case 1:
		return RFKILL_UNBLOCKED;
	case 2:
		return RFKILL_HARD_BLOCKED;
	default:
		nm_log_warn (LOGD_RFKILL, "unhandled rfkill state %d", sysfs_state);
		break;
	}
	return RFKILL_UNBLOCKED;
}

static void
recheck_killswitches (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	RfKillState poll_states[RFKILL_TYPE_MAX];
	int i;

	/* Default state is unblocked */
	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		poll_states[i] = RFKILL_UNBLOCKED;

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *ks = iter->data;
		GUdevDevice *device;
		RfKillState dev_state;

		device = g_udev_client_query_by_subsystem_and_name (priv->client, "rfkill", ks->name);
		if (!device)
			continue;

		dev_state = sysfs_state_to_nm_state (g_udev_device_get_property_as_int (device, "RFKILL_STATE"));
		if (dev_state > poll_states[ks->rtype])
			poll_states[ks->rtype] = dev_state;

		g_object_unref (device);
	}

	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		if (poll_states[i] != priv->rfkill_states[i]) {
			nm_log_dbg (LOGD_RFKILL, "%s rfkill state now '%s'",
			            rfkill_type_to_desc (i),
			            rfkill_state_to_desc (poll_states[i]));

			priv->rfkill_states[i] = poll_states[i];
			g_signal_emit (self, signals[RFKILL_CHANGED], 0, i, priv->rfkill_states[i]);
		}
	}
}

static Killswitch *
killswitch_find_by_name (NMUdevManager *self, const char *name)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (name != NULL, NULL);

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *candidate = iter->data;

		if (!strcmp (name, candidate->name))
			return candidate;
	}
	return NULL;
}

static const RfKillType
rfkill_type_to_enum (const char *str)
{
	g_return_val_if_fail (str != NULL, RFKILL_TYPE_UNKNOWN);

	if (!strcmp (str, "wlan"))
		return RFKILL_TYPE_WLAN;
	else if (!strcmp (str, "wwan"))
		return RFKILL_TYPE_WWAN;
	else if (!strcmp (str, "wimax"))
		return RFKILL_TYPE_WIMAX;

	return RFKILL_TYPE_UNKNOWN;
}

static void
add_one_killswitch (NMUdevManager *self, GUdevDevice *device)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *str_type;
	RfKillType rtype;
	Killswitch *ks;

	str_type = g_udev_device_get_property (device, "RFKILL_TYPE");
	rtype = rfkill_type_to_enum (str_type);
	if (rtype == RFKILL_TYPE_UNKNOWN)
		return;

	ks = killswitch_new (device, rtype);
	priv->killswitches = g_slist_prepend (priv->killswitches, ks);

	nm_log_info (LOGD_RFKILL, "found %s radio killswitch %s (at %s) (driver %s)",
	             rfkill_type_to_desc (rtype),
	             ks->name,
	             ks->path,
	             ks->driver ? ks->driver : "<unknown>");
}

static void
rfkill_add (NMUdevManager *self, GUdevDevice *device)
{
	const char *name;

	g_return_if_fail (device != NULL);
	name = g_udev_device_get_name (device);
	g_return_if_fail (name != NULL);

	if (!killswitch_find_by_name (self, name))
		add_one_killswitch (self, device);
}

static void
rfkill_remove (NMUdevManager *self,
               GUdevDevice *device)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	const char *name;

	g_return_if_fail (device != NULL);
	name = g_udev_device_get_name (device);
	g_return_if_fail (name != NULL);

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *ks = iter->data;

		if (!strcmp (ks->name, name)) {
			nm_log_info (LOGD_RFKILL, "radio killswitch %s disappeared", ks->path);
			priv->killswitches = g_slist_remove (priv->killswitches, ks);
			killswitch_destroy (ks);
			break;
		}
	}
}

static gboolean
is_wireless (GUdevDevice *device)
{
	char phy80211_path[255];
	struct stat s;
	int fd;
	struct iwreq iwr;
	const char *ifname, *path;
	gboolean is_wifi = FALSE;

	ifname = g_udev_device_get_name (device);
	g_assert (ifname);

	fd = socket (PF_INET, SOCK_DGRAM, 0);
	strncpy (iwr.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);

	path = g_udev_device_get_sysfs_path (device);
	snprintf (phy80211_path, sizeof (phy80211_path), "%s/phy80211", path);

	if (   (ioctl (fd, SIOCGIWNAME, &iwr) == 0)
	    || (stat (phy80211_path, &s) == 0 && (s.st_mode & S_IFDIR)))
		is_wifi = TRUE;

	close (fd);
	return is_wifi;
}

static gboolean
is_olpc_mesh (GUdevDevice *device)
{
	const gchar *prop = g_udev_device_get_property (device, "ID_NM_OLPC_MESH");
	return (prop != NULL);
}

static GObject *
device_creator (NMUdevManager *manager,
                GUdevDevice *udev_device,
                gboolean sleeping)
{
	GObject *device = NULL;
	const char *ifname, *driver, *path, *subsys;
	GUdevDevice *parent = NULL, *grandparent = NULL;
	gint ifindex;

	ifname = g_udev_device_get_name (udev_device);
	g_assert (ifname);

	path = g_udev_device_get_sysfs_path (udev_device);
	if (!path) {
		nm_log_warn (LOGD_HW, "couldn't determine device path; ignoring...");
		return NULL;
	}

	driver = g_udev_device_get_driver (udev_device);
	if (!driver) {
		/* Try the parent */
		parent = g_udev_device_get_parent (udev_device);
		if (parent) {
			driver = g_udev_device_get_driver (parent);
			if (!driver) {
				/* try the grandparent only if it's an ibmebus device */
				subsys = g_udev_device_get_subsystem (parent);
				if (subsys && !strcmp (subsys, "ibmebus")) {
					grandparent = g_udev_device_get_parent (parent);
					if (grandparent)
						driver = g_udev_device_get_driver (grandparent);
				}
			}
		}
	}

	if (!driver) {
		nm_log_warn (LOGD_HW, "%s: couldn't determine device driver; ignoring...", path);
		goto out;
	}

	ifindex = g_udev_device_get_sysfs_attr_as_int (udev_device, "ifindex");
	if (ifindex <= 0) {
		nm_log_warn (LOGD_HW, "%s: device had invalid ifindex %d; ignoring...", path, (guint32) ifindex);
		goto out;
	}

	if (is_olpc_mesh (udev_device)) /* must be before is_wireless */
		device = (GObject *) nm_device_olpc_mesh_new (path, ifname, driver);
	else if (is_wireless (udev_device))
		device = (GObject *) nm_device_wifi_new (path, ifname, driver);
	else
		device = (GObject *) nm_device_ethernet_new (path, ifname, driver);

out:
	if (grandparent)
		g_object_unref (grandparent);
	if (parent)
		g_object_unref (parent);
	return device;
}

static void
net_add (NMUdevManager *self, GUdevDevice *device)
{
	gint etype;
	const char *iface;
	const char *devtype;

	g_return_if_fail (device != NULL);

	etype = g_udev_device_get_sysfs_attr_as_int (device, "type");
	if (etype != 1) {
		nm_log_dbg (LOGD_HW, "ignoring interface with type %d", etype);
		return; /* Not using ethernet encapsulation, don't care */
	}

	/* Not all ethernet devices are immediately usable; newer mobile broadband
	 * devices (Ericsson, Option, Sierra) require setup on the tty before the
	 * ethernet device is usable.  2.6.33 and later kernels set the 'DEVTYPE'
	 * uevent variable which we can use to ignore the interface as a NMDevice
	 * subclass.  ModemManager will pick it up though and so we'll handle it
	 * through the mobile broadband stuff.
	 */
	devtype = g_udev_device_get_property (device, "DEVTYPE");
	if (devtype && !strcmp (devtype, "wwan")) {
		nm_log_dbg (LOGD_HW, "ignoring interface with devtype '%s'", devtype);
		return;
	}

	iface = g_udev_device_get_name (device);
	if (!iface) {
		nm_log_dbg (LOGD_HW, "failed to get device's interface");
		return;
	}

	g_signal_emit (self, signals[DEVICE_ADDED], 0, device, device_creator);
}

static void
net_remove (NMUdevManager *self, GUdevDevice *device)
{
	g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
}

void
nm_udev_manager_query_devices (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	GList *devices, *iter;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_UDEV_MANAGER (self));

	devices = g_udev_client_query_by_subsystem (priv->client, "net");
	for (iter = devices; iter; iter = g_list_next (iter)) {
		net_add (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (devices);
}

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	NMUdevManager *self = NM_UDEV_MANAGER (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (subsys != NULL);

	nm_log_dbg (LOGD_HW, "UDEV event: action '%s' subsys '%s' device '%s'",
	            action, subsys, g_udev_device_get_name (device));

	g_return_if_fail (!strcmp (subsys, "rfkill") || !strcmp (subsys, "net"));

	if (!strcmp (action, "add")) {
		if (!strcmp (subsys, "rfkill"))
			rfkill_add (self, device);
		else if (!strcmp (subsys, "net"))
			net_add (self, device);
	} else if (!strcmp (action, "remove")) {
		if (!strcmp (subsys, "rfkill"))
			rfkill_remove (self, device);
		else if (!strcmp (subsys, "net"))
			net_remove (self, device);
	}

	recheck_killswitches (self);
}

static void
nm_udev_manager_init (NMUdevManager *self)
{
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);
	const char *subsys[3] = { "rfkill", "net", NULL };
	GList *switches, *iter;
	guint32 i;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->rfkill_states[i] = RFKILL_UNBLOCKED;

	priv->client = g_udev_client_new (subsys);
	g_signal_connect (priv->client, "uevent", G_CALLBACK (handle_uevent), self);

	switches = g_udev_client_query_by_subsystem (priv->client, "rfkill");
	for (iter = switches; iter; iter = g_list_next (iter)) {
		add_one_killswitch (self, G_UDEV_DEVICE (iter->data));
		g_object_unref (G_UDEV_DEVICE (iter->data));
	}
	g_list_free (switches);

	recheck_killswitches (self);
}

static void
dispose (GObject *object)
{
	NMUdevManager *self = NM_UDEV_MANAGER (object);
	NMUdevManagerPrivate *priv = NM_UDEV_MANAGER_GET_PRIVATE (self);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_udev_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_object_unref (priv->client);

	g_slist_foreach (priv->killswitches, (GFunc) killswitch_destroy, NULL);
	g_slist_free (priv->killswitches);

	G_OBJECT_CLASS (nm_udev_manager_parent_class)->dispose (object);	
}

static void
nm_udev_manager_class_init (NMUdevManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMUdevManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, device_added),
					  NULL, NULL,
					  _nm_marshal_VOID__POINTER_POINTER,
					  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_POINTER);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[RFKILL_CHANGED] =
		g_signal_new ("rfkill-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMUdevManagerClass, rfkill_changed),
					  NULL, NULL,
					  _nm_marshal_VOID__UINT_UINT,
					  G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}

