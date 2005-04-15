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


struct NMVPNConnection
{
	int			 refcount;
	char			*name;
	char			*user_name;
	NMVPNService	*service;
};


NMVPNConnection *nm_vpn_connection_new (const char *name, const char *user_name, NMVPNService *service)
{
	NMVPNConnection	*connection;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (user_name != NULL, NULL);
	g_return_val_if_fail (service != NULL, NULL);


	connection = g_malloc0 (sizeof (NMVPNConnection));
	connection->refcount = 1;

	connection->name = g_strdup (name);
	connection->user_name = g_strdup (user_name);

	nm_vpn_service_ref (service);
	connection->service = service;

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
		nm_vpn_service_unref (connection->service);

		memset (connection, 0, sizeof (NMVPNConnection));
		g_free (connection);
	}
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

NMVPNService *nm_vpn_connection_get_service (NMVPNConnection *connection)
{
	g_return_val_if_fail (connection != NULL, NULL);

	return connection->service;
}

