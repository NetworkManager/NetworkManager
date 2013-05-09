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

#include <config.h>

#include <string.h>
#include <gudev/gudev.h>

#include "nm-rfkill-manager.h"
#include "nm-logging.h"

typedef struct {
	GUdevClient *client;

	/* Authoritative rfkill state (RFKILL_* enum) */
	RfKillState rfkill_states[RFKILL_TYPE_MAX];
	GSList *killswitches;

} NMRfkillManagerPrivate;

#define NM_RFKILL_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_RFKILL_MANAGER, NMRfkillManagerPrivate))

G_DEFINE_TYPE (NMRfkillManager, nm_rfkill_manager, G_TYPE_OBJECT)

enum {
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
killswitch_new (GUdevDevice *device, RfKillType rtype)
{
	Killswitch *ks;
	GUdevDevice *parent = NULL, *grandparent = NULL;
	const char *driver, *subsys, *parent_subsys = NULL;

	ks = g_malloc0 (sizeof (Killswitch));
	ks->name = g_strdup (g_udev_device_get_name (device));
	ks->seqnum = g_udev_device_get_seqnum (device);
	ks->path = g_strdup (g_udev_device_get_sysfs_path (device));
	ks->rtype = rtype;

	driver = g_udev_device_get_property (device, "DRIVER");
	subsys = g_udev_device_get_subsystem (device);

	/* Check parent for various attributes */
	parent = g_udev_device_get_parent (device);
	if (parent) {
		parent_subsys = g_udev_device_get_subsystem (parent);
		if (!driver)
			driver = g_udev_device_get_property (parent, "DRIVER");
		if (!driver) {
			/* Sigh; try the grandparent */
			grandparent = g_udev_device_get_parent (parent);
			if (grandparent)
				driver = g_udev_device_get_property (grandparent, "DRIVER");
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

	if (grandparent)
		g_object_unref (grandparent);
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

NMRfkillManager *
nm_rfkill_manager_new (void)
{
	return NM_RFKILL_MANAGER (g_object_new (NM_TYPE_RFKILL_MANAGER, NULL));
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
		GUdevDevice *device;
		RfKillState dev_state;
		int sysfs_state;

		device = g_udev_client_query_by_subsystem_and_name (priv->client, "rfkill", ks->name);
		if (device) {
			sysfs_state = g_udev_device_get_property_as_int (device, "RFKILL_STATE");
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
			g_object_unref (device);
		}
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
add_one_killswitch (NMRfkillManager *self, GUdevDevice *device)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	const char *str_type;
	RfKillType rtype;
	Killswitch *ks;

	str_type = g_udev_device_get_property (device, "RFKILL_TYPE");
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
	             ks->driver ? ks->driver : "<unknown>");
}

static void
rfkill_add (NMRfkillManager *self, GUdevDevice *device)
{
	const char *name;

	g_return_if_fail (device != NULL);
	name = g_udev_device_get_name (device);
	g_return_if_fail (name != NULL);

	if (!killswitch_find_by_name (self, name))
		add_one_killswitch (self, device);
}

static void
rfkill_remove (NMRfkillManager *self,
               GUdevDevice *device)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
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

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
	NMRfkillManager *self = NM_RFKILL_MANAGER (user_data);
	const char *subsys;

	g_return_if_fail (action != NULL);

	/* A bit paranoid */
	subsys = g_udev_device_get_subsystem (device);
	g_return_if_fail (!g_strcmp0 (subsys, "rfkill"));

	nm_log_dbg (LOGD_HW, "udev rfkill event: action '%s' device '%s'",
	            action, g_udev_device_get_name (device));

	if (!strcmp (action, "add"))
		rfkill_add (self, device);
	else if (!strcmp (action, "remove"))
		rfkill_remove (self, device);

	recheck_killswitches (self);
}

static void
nm_rfkill_manager_init (NMRfkillManager *self)
{
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);
	const char *subsys[] = { "rfkill", NULL };
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
	NMRfkillManager *self = NM_RFKILL_MANAGER (object);
	NMRfkillManagerPrivate *priv = NM_RFKILL_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->client);

	if (priv->killswitches) {
		g_slist_free_full (priv->killswitches, (GDestroyNotify) killswitch_destroy);
		priv->killswitches = NULL;
	}

	G_OBJECT_CLASS (nm_rfkill_manager_parent_class)->dispose (object);	
}

static void
nm_rfkill_manager_class_init (NMRfkillManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMRfkillManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	/* Signals */
	signals[RFKILL_CHANGED] =
		g_signal_new ("rfkill-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMRfkillManagerClass, rfkill_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);
}
