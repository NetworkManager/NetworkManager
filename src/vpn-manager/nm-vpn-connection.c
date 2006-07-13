/* nm-vpn-connection.c - handle a single VPN connections within NetworkManager's framework 
 *
 * Copyright (C) 2005 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"
#include <glib.h>
#include <string.h>
#include "nm-vpn-connection.h"
#include "nm-dbus-vpn.h"
#include "NetworkManagerSystem.h"


struct NMVPNConnection
{
	int			refcount;

	/* Won't change over life of object */
	char *		name;
	char *		user_name;
	char *		service_name;

	NMNamedManager *named_manager;
	DBusConnection *dbus_connection;

	/* Change when connection is activated/deactivated */
	NMDevice *	parent_dev;
	NMIP4Config *	ip4_config;
	char *		vpn_iface;
};


static void	nm_vpn_connection_set_vpn_iface	(NMVPNConnection *con, const char *vpn_iface);
static void	nm_vpn_connection_set_ip4_config	(NMVPNConnection *con, NMIP4Config *ip4_config);
static void	nm_vpn_connection_set_parent_device(NMVPNConnection *con, NMDevice *parent_dev);


NMVPNConnection *nm_vpn_connection_new (const char *name, const char *user_name, const char *service_name,
								NMNamedManager *named_manager, DBusConnection *dbus_connection)
{
	NMVPNConnection	*connection;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (user_name != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);
	g_return_val_if_fail (named_manager != NULL, NULL);
	g_return_val_if_fail (dbus_connection != NULL, NULL);

	connection = g_malloc0 (sizeof (NMVPNConnection));
	connection->refcount = 1;

	connection->name = g_strdup (name);
	connection->user_name = g_strdup (user_name);
	connection->service_name = g_strdup (service_name);

	g_object_ref (named_manager);
	connection->named_manager = named_manager;

	connection->dbus_connection = dbus_connection;

	return connection;
}


void nm_vpn_connection_ref (NMVPNConnection *connection)
{
	g_return_if_fail (connection != NULL);

	connection->refcount++;
}

void nm_vpn_connection_unref (NMVPNConnection *connection)
{
	g_return_if_fail (connection != NULL);

	connection->refcount--;
	if (connection->refcount <= 0)
	{
		g_free (connection->name);
		g_free (connection->user_name);
		g_free (connection->service_name);

		if (connection->parent_dev)
			g_object_unref (G_OBJECT (connection->parent_dev));
		if (connection->ip4_config)
			nm_ip4_config_unref (connection->ip4_config);
		g_free (connection->vpn_iface);

		g_object_unref (connection->named_manager);

		memset (connection, 0, sizeof (NMVPNConnection));
		g_free (connection);
	}
}


void nm_vpn_connection_activate (NMVPNConnection *connection)
{
	g_return_if_fail (connection != NULL);

	/* Nothing done here yet */
}


gboolean nm_vpn_connection_set_config (NMVPNConnection *connection, const char *vpn_iface, NMDevice *dev, NMIP4Config *ip4_config)
{
	gboolean	success = FALSE;
	int		num_routes = -1;
	char **	routes;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (ip4_config != NULL, FALSE);

	/* IPsec VPNs will not have tunnel device */
	if (vpn_iface != NULL && strlen (vpn_iface))
		nm_vpn_connection_set_vpn_iface (connection, vpn_iface);
	nm_vpn_connection_set_parent_device (connection, dev);
	nm_vpn_connection_set_ip4_config (connection, ip4_config);

	routes = nm_dbus_vpn_get_routes (connection->dbus_connection, connection, &num_routes);
	nm_system_vpn_device_set_from_ip4_config (connection->named_manager, connection->parent_dev,
				connection->vpn_iface, connection->ip4_config, routes, num_routes);
	g_strfreev(routes);
	success = TRUE;

	return success;
}


void nm_vpn_connection_deactivate (NMVPNConnection *connection)
{
	g_return_if_fail (connection != NULL);

	if (connection->vpn_iface)
	{
		nm_system_device_set_up_down_with_iface (connection->vpn_iface, FALSE);
		nm_system_device_flush_routes_with_iface (connection->vpn_iface);
		nm_system_device_flush_addresses_with_iface (connection->vpn_iface);
	}

	if (connection->ip4_config)
	{
		/* Remove attributes of the VPN's IP4 Config */
		nm_system_vpn_device_unset_from_ip4_config (connection->named_manager, connection->parent_dev,
				connection->vpn_iface, connection->ip4_config);

		/* Reset routes, nameservers, and domains of the currently active device */
		nm_system_device_set_from_ip4_config (connection->parent_dev);
	}

	nm_vpn_connection_set_ip4_config (connection, NULL);
	nm_vpn_connection_set_vpn_iface (connection, NULL);
	nm_vpn_connection_set_parent_device (connection, NULL);
}


const char *nm_vpn_connection_get_name (NMVPNConnection *connection)
{
	g_return_val_if_fail (connection != NULL, NULL);

	return connection->name;
}

const char *nm_vpn_connection_get_user_name (NMVPNConnection *connection)
{
	g_return_val_if_fail (connection != NULL, NULL);

	return connection->user_name;
}

const char  *nm_vpn_connection_get_service_name (NMVPNConnection *connection)
{
	g_return_val_if_fail (connection != NULL, NULL);

	return connection->service_name;
}


static void nm_vpn_connection_set_vpn_iface (NMVPNConnection *con, const char *vpn_iface)
{
	g_return_if_fail (con != NULL);

	if (con->vpn_iface)
	{
		g_free (con->vpn_iface);
		con->vpn_iface = NULL;
	}

	if (vpn_iface)
		con->vpn_iface = g_strdup (vpn_iface);
}

static void nm_vpn_connection_set_ip4_config (NMVPNConnection *con, NMIP4Config *ip4_config)
{
	g_return_if_fail (con != NULL);

	if (con->ip4_config)
	{
		nm_ip4_config_unref (con->ip4_config);
		con->ip4_config = NULL;
	}

	if (ip4_config)
	{
		nm_ip4_config_ref (ip4_config);
		con->ip4_config = ip4_config;
	}
}

static void nm_vpn_connection_set_parent_device (NMVPNConnection *con, NMDevice *parent_dev)
{
	g_return_if_fail (con != NULL);

	if (con->parent_dev)
	{
		g_object_unref (G_OBJECT (con->parent_dev));
		con->parent_dev = NULL;
	}

	if (parent_dev)
	{
		g_object_ref (G_OBJECT (parent_dev));
		con->parent_dev = parent_dev;
	}
}
