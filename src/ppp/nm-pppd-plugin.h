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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#define NM_DBUS_INTERFACE_PPP  "org.freedesktop.NetworkManager.PPP"

#define NM_PPP_IP4_CONFIG_INTERFACE "interface"
#define NM_PPP_IP4_CONFIG_ADDRESS   "address"
#define NM_PPP_IP4_CONFIG_PREFIX    "prefix"
#define NM_PPP_IP4_CONFIG_GATEWAY   "gateway"
#define NM_PPP_IP4_CONFIG_DNS       "dns"
#define NM_PPP_IP4_CONFIG_WINS      "wins"

#define NM_PPP_IP6_CONFIG_INTERFACE "interface"
#define NM_PPP_IP6_CONFIG_OUR_IID   "our-iid"
#define NM_PPP_IP6_CONFIG_PEER_IID  "peer-iid"

