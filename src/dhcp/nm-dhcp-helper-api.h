/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_DHCP_HELPER_API_H__
#define __NM_DHCP_HELPER_API_H__

/*****************************************************************************/

#define NM_DHCP_CLIENT_DBUS_IFACE "org.freedesktop.nm_dhcp_client"

#define NM_DHCP_HELPER_SERVER_BUS_NAME          "org.freedesktop.nm_dhcp_server"
#define NM_DHCP_HELPER_SERVER_OBJECT_PATH       "/org/freedesktop/nm_dhcp_server"
#define NM_DHCP_HELPER_SERVER_INTERFACE_NAME    "org.freedesktop.nm_dhcp_server"
#define NM_DHCP_HELPER_SERVER_METHOD_NOTIFY     "Notify"

/*****************************************************************************/

#endif /* __NM_DHCP_HELPER_API_H__ */
