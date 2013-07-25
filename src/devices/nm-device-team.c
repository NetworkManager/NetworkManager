/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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
 */

#include "config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <netinet/ether.h>

#include "nm-device-team.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-platform.h"
#include "nm-dbus-glib-types.h"
#include "nm-dbus-manager.h"
#include "nm-enum-types.h"

#include "nm-device-team-glue.h"


G_DEFINE_TYPE (NMDeviceTeam, nm_device_team, NM_TYPE_DEVICE)

#define NM_DEVICE_TEAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_TEAM, NMDeviceTeamPrivate))

#define NM_TEAM_ERROR (nm_team_error_quark ())

typedef struct {
	int dummy;
} NMDeviceTeamPrivate;

enum {
	PROP_0,
	PROP_SLAVES,

	LAST_PROP
};

/******************************************************************/

static GQuark
nm_team_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-team-error");
	return quark;
}

/******************************************************************/

static guint32
get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_CARRIER_DETECT;
}

static gboolean
is_available (NMDevice *dev)
{
	if (NM_DEVICE_GET_CLASS (dev)->is_up)
		return NM_DEVICE_GET_CLASS (dev)->is_up (dev);
	return FALSE;
}

static gboolean
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	const char *iface;
	NMSettingTeam *s_team;

	if (!NM_DEVICE_CLASS (nm_device_team_parent_class)->check_connection_compatible (device, connection, error))
		return FALSE;

	s_team = nm_connection_get_setting_team (connection);
	if (!s_team || !nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME)) {
		g_set_error (error, NM_TEAM_ERROR, NM_TEAM_ERROR_CONNECTION_NOT_TEAM,
		             "The connection was not a team connection.");
		return FALSE;
	}

	/* Team connections must specify the virtual interface name */
	iface = nm_connection_get_virtual_iface_name (connection);
	if (!iface || strcmp (nm_device_get_iface (device), iface)) {
		g_set_error (error, NM_TEAM_ERROR, NM_TEAM_ERROR_CONNECTION_NOT_TEAM,
		             "The team connection virtual interface name did not match.");
		return FALSE;
	}

	/* FIXME: match team properties like mode, etc? */

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingTeam *s_team, *tmp;
	guint32 i = 0;
	char *name;
	const GSList *iter;
	gboolean found;

	nm_utils_complete_generic (connection,
	                           NM_SETTING_TEAM_SETTING_NAME,
	                           existing_connections,
	                           _("Team connection %d"),
	                           NULL,
	                           TRUE);

	s_team = nm_connection_get_setting_team (connection);
	if (!s_team) {
		s_team = (NMSettingTeam *) nm_setting_team_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_team));
	}

	/* Grab the first name that doesn't exist in either our connections
	 * or a device on the system.
	 */
	while (i < 500 && !nm_setting_team_get_interface_name (s_team)) {
		name = g_strdup_printf ("team%u", i);
		/* check interface names */
		if (!nm_platform_link_exists (name)) {
			/* check existing team connections */
			for (iter = existing_connections, found = FALSE; iter; iter = g_slist_next (iter)) {
				NMConnection *candidate = iter->data;

				tmp = nm_connection_get_setting_team (candidate);
				if (tmp && nm_connection_is_type (candidate, NM_SETTING_TEAM_SETTING_NAME)) {
					if (g_strcmp0 (nm_setting_team_get_interface_name (tmp), name) == 0) {
						found = TRUE;
						break;
					}
				}
			}

			if (!found)
				g_object_set (G_OBJECT (s_team), NM_SETTING_TEAM_INTERFACE_NAME, name, NULL);
		}

		g_free (name);
		i++;
	}

	return TRUE;
}

static gboolean
match_l2_config (NMDevice *self, NMConnection *connection)
{
	/* FIXME */
	return TRUE;
}

/******************************************************************/

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMConnection *connection;
	NMSettingTeam *s_team;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_team_parent_class)->act_stage1_prepare (dev, reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		connection = nm_device_get_connection (dev);
		g_assert (connection);
		s_team = nm_connection_get_setting_team (connection);
		g_assert (s_team);
	}
	return ret;
}

static gboolean
enslave_slave (NMDevice *device, NMDevice *slave, NMConnection *connection)
{
	gboolean success, no_firmware = FALSE;
	const char *iface = nm_device_get_ip_iface (device);
	const char *slave_iface = nm_device_get_ip_iface (slave);

	nm_device_take_down (slave, TRUE);

	success = nm_platform_link_enslave (nm_device_get_ip_ifindex (device),
	                                    nm_device_get_ip_ifindex (slave));

	nm_device_bring_up (slave, TRUE, &no_firmware);

	if (success) {
		nm_log_info (LOGD_TEAM, "(%s): enslaved team port %s", iface, slave_iface);
		g_object_notify (G_OBJECT (device), "slaves");
	}

	return success;
}

static gboolean
release_slave (NMDevice *device, NMDevice *slave)
{
	gboolean success, no_firmware = FALSE;

	success = nm_platform_link_release (nm_device_get_ip_ifindex (device),
	                                    nm_device_get_ip_ifindex (slave));

	nm_log_info (LOGD_TEAM, "(%s): released team port %s (success %d)",
	             nm_device_get_ip_iface (device),
	             nm_device_get_ip_iface (slave),
	             success);
	g_object_notify (G_OBJECT (device), "slaves");

	/* Kernel team code "closes" the port when releasing it, (which clears
	 * IFF_UP), so we must bring it back up here to ensure carrier changes and
	 * other state is noticed by the now-released port.
	 */
	if (!nm_device_bring_up (slave, TRUE, &no_firmware)) {
		nm_log_warn (LOGD_TEAM, "(%s): released team port could not be brought up.",
		             nm_device_get_iface (slave));
	}

	return success;
}

/******************************************************************/

NMDevice *
nm_device_team_new (const char *iface)
{
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_TEAM,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, "team",
	                                  NM_DEVICE_TYPE_DESC, "Team",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_TEAM,
	                                  NM_DEVICE_IS_MASTER, TRUE,
	                                  NULL);
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_device_team_parent_class)->constructed (object);

	nm_log_dbg (LOGD_HW | LOGD_TEAM, "(%s): kernel ifindex %d",
	            nm_device_get_iface (NM_DEVICE (object)),
	            nm_device_get_ifindex (NM_DEVICE (object)));
}

static void
nm_device_team_init (NMDeviceTeam * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	GPtrArray *slaves;
	GSList *list, *iter;

	switch (prop_id) {
		break;
	case PROP_SLAVES:
		slaves = g_ptr_array_new ();
		list = nm_device_master_get_slaves (NM_DEVICE (object));
		for (iter = list; iter; iter = iter->next)
			g_ptr_array_add (slaves, g_strdup (nm_device_get_path (NM_DEVICE (iter->data))));
		g_slist_free (list);
		g_value_take_boxed (value, slaves);
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
nm_device_team_class_init (NMDeviceTeamClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceTeamPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->is_available = is_available;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;

	parent_class->match_l2_config = match_l2_config;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->enslave_slave = enslave_slave;
	parent_class->release_slave = release_slave;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_TEAM_SLAVES,
		                     "Slaves",
		                     "Slaves",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_team_object_info);

	dbus_g_error_domain_register (NM_TEAM_ERROR, NULL, NM_TYPE_TEAM_ERROR);
}
