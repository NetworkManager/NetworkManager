/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * 
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef DHCPCD_H
#define DHCPCD_H

#include <time.h>

#define DHCP_DEFAULT_TIMEOUT		60
#define DHCP_DEFAULT_LEASETIME	0xffffffff	/* infinite lease time */
#define DHCP_CLASS_ID_MAX_LEN		48
#define DHCP_CLIENT_ID_MAX_LEN	48
#define DHCP_HOSTNAME_MAX_LEN		64


/* Return codes */
#define RET_DHCP_ERROR			0
#define RET_DHCP_ADDRESS_IN_USE	1
#define RET_DHCP_TIMEOUT			2
#define RET_DHCP_CEASED			3
#define RET_DHCP_NAK			4
#define RET_DHCP_SUCCESS			5
#define RET_DHCP_BOUND			6


typedef struct dhcp_client_options
{
	unsigned char	host_name[DHCP_HOSTNAME_MAX_LEN];
	unsigned char	class_id[DHCP_CLASS_ID_MAX_LEN];
	unsigned char	client_id[DHCP_CLIENT_ID_MAX_LEN];
	int			do_rfc1541;
	int			do_broadcast_response;
	time_t		base_timeout;
	int			do_checksum;
	int			send_second_discover;
	int			window;
} dhcp_client_options;

struct dhcp_interface *dhcp_interface_init (const char *if_name, dhcp_client_options *in_opts);
void dhcp_interface_free (struct dhcp_interface *iface);
void dhcp_interface_cease (struct dhcp_interface *iface);

int dhcp_interface_dhcp_field_exists (struct dhcp_interface *iface, int val);
int dhcp_interface_get_dhcp_field_len (struct dhcp_interface *iface, int val);
void *dhcp_interface_get_dhcp_field (struct dhcp_interface *iface, int val);
int dhcp_individual_value_len (int val);

#endif
