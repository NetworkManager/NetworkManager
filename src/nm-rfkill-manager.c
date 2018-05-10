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
 * Copyright (C) 2009 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-rfkill-manager.h"

#include <string.h>
#include <libudev.h>

#include "nm-utils/nm-udev-utils.h"

/*****************************************************************************/

enum {
	RFKILL_CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMUdevClient *udev_client;

	/* Authoritative rfkill state (RFKILL_* enum) */
	RfKillState rfkill_states[RFKILL_TYPE_MAX];
	GSList *killswitches;
} NMRfkillManagerPrivate;

struct _NMRfkillManager {
	GObject parent;
	NMRfkillManagerPrivate _priv;
};

struct _NMRfkillManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMRfkillManager, nm_rfkill_manager, G_TYPE_OBJECT)

#define NM_RFKILL_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMRfkillManager, NM_IS_RFKILL_MANAGER)

/*****************************************************************************/

typedef struct {
	char *name;
	guint64 seqnum;
	char *path;
	char *driver;
	RfKillType rtype;
	gint state;
	gboolean platform;
} Killswitch;

RfKillState
nm_rfkill_manager_get_rfkill_state (NMRfkillManager *self, RfKillType rtype)
{
	g_return_val_if_fail (self != NULL, RFKILL_UNBLOCKED);
	g_return_val_if_fail (rtype < RFKILL_TYPE_MAX, RFKILL_UNBLOCKED);

	return NM_RFKILL_MANAGER_GET_PRIVATE (self)->rfkill_states[rtype];
}

static const char *
rfkill_type_to_desc (RfKillType rtype)
{
	if (rtype == 0)
		return "WiFi";
	else if (rtype == 1)
		return "WWAN";
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
killswitch_new (struct udev_device *device, RfKillType rtype)
{
	Killswitch *ks;
	struct udev_device *parent = NULL, *grandparent = NULL;
	const char *driver, *subsys, *parent_subsys = NULL;

	ks = g_malloc0 (sizeof (Killswitch));
	ks->name = g_strdup (udev_device_get_sysname (device));
	ks->seqnum = udev_device_get_seqnum (device);
	ks->path = g_strdup (udev_device_get_syspath (device));
	ks->rtype = rtype;

	driver = udev_device_get_property_value (device, "DRIVER");
	subsys = udev_device_get_subsystem (device);

	/* Check parent for various attributes */
	parent = udev_device_get_parent (device);
	if (parent) {
		parent_subsys = udev_device_get_subsystem (parent);
		if (!driver)
			driver = udev_device_get_property_value (parent, "DRIVER");
		if (!driver) {
			/* Sigh; try the grandparent */
			grandparent = udev_device_get_parent (parent);
			if (grandparent)
				driver = udev_device_get_property_value (grandparent, "DRIVER");
		}
	}

	if (!driver)
		driver = "(unknown)";
	ks->driver = g_strdup (driver);

	if (   g_strcmp0 (subsys, "platform") == 0
	    || g_strcmp0 (parent_subsys, "platform") == 0
	    || g_strcmp0 (subsys, "acpi") == 0
	    || g_strcmp0 (parent_subsys, "acpi") == 0)
		ks->platform = TRUE;

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
recheck_killswitches (NMRfkillManager *self)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	RfKillState poll_states[RFKILL_TYPE_MAX];
	RfKillState platform_states[RFKILL_TYPE_MAX];
	gboolean platform_checked[RFKILL_TYPE_MAX];
	int i;

	/* Default state is unblocked */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		poll_states[i] = RFKILL_UNBLOCKED;
		platform_states[i] = RFKILL_UNBLOCKED;
		platform_checked[i] = FALSE;
	}

	/* Poll the states of all killswitches */
	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *ks = iter->data;
		struct udev_device *device;
		RfKillState dev_state;
		int sysfs_state;

		device = udev_device_new_from_subsystem_sysname (nm_udev_client_get_udev (priv->udev_client),
		                                                 "rfkill", ks->name);
		if (!device)
			continue;
		sysfs_state = _nm_utils_ascii_str_to_int64 (udev_device_get_property_value (device, "RFKILL_STATE"),
		                                            10, G_MININT, G_MAXINT, -1);
		dev_state = sysfs_state_to_nm_state (sysfs_state);

		nm_log_dbg (LOGD_RFKILL, "%s rfkill%s switch %s state now %d/%u",
		            rfkill_type_to_desc (ks->rtype),
		            ks->platform ? " platform" : "",
		            ks->name,
		            sysfs_state,
		            dev_state);

		if (ks->platform == FALSE) {
			if (dev_state > poll_states[ks->rtype])
				poll_states[ks->rtype] = dev_state;
		} else {
			platform_checked[ks->rtype] = TRUE;
			if (dev_state > platform_states[ks->rtype])
				platform_states[ks->rtype] = dev_state;
		}
		udev_device_unref (device);
	}

	/* Log and emit change signal for final rfkill states */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		if (platform_checked[i] == TRUE) {
			/* blocked platform switch state overrides device state, otherwise
			 * let the device state stand. (bgo #655773)
			 */
			if (platform_states[i] != RFKILL_UNBLOCKED)
				poll_states[i] = platform_states[i];
		}

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
killswitch_find_by_name (NMRfkillManager *self, const char *name)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	g_return_val_if_fail (name != NULL, NULL);

	for (iter = priv->killswitches; iter; iter = g_slist_next (iter)) {
		Killswitch *candidate = iter->data;

		if (!strcmp (name, candidate->name))
			return candidate;
	}
	return NULL;
}

static RfKillType
rfkill_type_to_enum (const char *str)
{
	g_return_val_if_fail (str != NULL, RFKILL_TYPE_UNKNOWN);

	if (!strcmp (str, "wlan"))
		return RFKILL_TYPE_WLAN;
	else if (!strcmp (str, "wwan"))
		return RFKILL_TYPE_WWAN;

	return RFKILL_TYPE_UNKNOWN;
}

static void
add_one_killswitch (NMRfkillManager *self, struct udev_device *device)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	const char *str_type;
	RfKillType rtype;
	Killswitch *ks;

	str_type = udev_device_get_property_value (device, "RFKILL_TYPE");
	rtype = rfkill_type_to_enum (str_type);
	if (rtype == RFKILL_TYPE_UNKNOWN)
		return;

	ks = killswitch_new (device, rtype);
	priv->killswitches = g_slist_prepend (priv->killswitches, ks);

	nm_log_info (LOGD_RFKILL, "%s: found %s radio killswitch (at %s) (%sdriver %s)",
	             ks->name,
	             rfkill_type_to_desc (rtype),
	             ks->path,
	             ks->platform ? "platform " : "",
	             ks->driver ?: "<unknown>");
}

static void
rfkill_add (NMRfkillManager *self, struct udev_device *device)
{
	const char *name;

	g_return_if_fail (device != NULL);
	name = udev_device_get_sysname (device);
	g_return_if_fail (name != NULL);

	if (!killswitch_find_by_name (self, name))
		add_one_killswitch (self, device);
}

static void
rfkill_remove (NMRfkillManager *self,
               struct udev_device *device)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	const char *name;

	g_return_if_fail (device != NULL);
	name = udev_device_get_sysname (device);
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

static void
handle_uevent (NMUdevClient *client,
               struct udev_device *device,
               gpointer user_data)
{
	NMRfkillManager *self = NM_RFKILL_MANAGER (user_data);
	const char *subsys;
	const char *action;

	action = udev_device_get_action (device);

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = udev_device_get_subsystem (device);
	g_return_if_fail (!g_strcmp0 (subsys, "rfkill"));

	nm_log_dbg (LOGD_PLATFORM, "udev rfkill event: action '%s' device '%s'",
	            action, udev_device_get_sysname (device));

	if (!strcmp (action, "add"))
		rfkill_add (self, device);
	else if (!strcmp (action, "remove"))
		rfkill_remove (self, device);

	recheck_killswitches (self);
}

/*****************************************************************************/

static void
nm_rfkill_manager_init (NMRfkillManager *self)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	struct udev_enumerate *enumerate;
	struct udev_list_entry *iter;
	guint i;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->rfkill_states[i] = RFKILL_UNBLOCKED;

	priv->udev_client = nm_udev_client_new ((const char *[]) { "rfkill", NULL },
	                                        handle_uevent, self);

	enumerate = nm_udev_client_enumerate_new (priv->udev_client);
	udev_enumerate_scan_devices (enumerate);
	iter = udev_enumerate_get_list_entry (enumerate);
	for (; iter; iter = udev_list_entry_get_next (iter)) {
		struct udev_device *udevice;

		udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerate),
		                                        udev_list_entry_get_name (iter));
		if (!udevice)
			continue;

		add_one_killswitch (self, udevice);
		udev_device_unref (udevice);
	}
	udev_enumerate_unref (enumerate);

	recheck_killswitches (self);
}

NMRfkillManager *
nm_rfkill_manager_new (void)
{
	return NM_RFKILL_MANAGER (g_object_new (NM_TYPE_RFKILL_MANAGER, NULL));
}

static void
dispose (GObject *object)
{
	NMRfkillManager *self = NM_RFKILL_MANAGER (object);
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);

	if (priv->killswitches) {
		g_slist_free_full (priv->killswitches, (GDestroyNotify) killswitch_destroy);
		priv->killswitches = NULL;
	}

	priv->udev_client = nm_udev_client_unref (priv->udev_client);

	G_OBJECT_CLASS (nm_rfkill_manager_parent_class)->dispose (object);
}

static void
nm_rfkill_manager_class_init (NMRfkillManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;

	signals[RFKILL_CHANGED] =
	    g_signal_new (NM_RFKILL_MANAGER_SIGNAL_RFKILL_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}
