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
 * along with this program; if not, write to the Free Softwarme
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include "client.h"
#include "buildmsg.h"

extern int		DebugFlag;

/*****************************************************************************/
void fill_common_fields (dhcp_interface *iface, dhcpMessage *dhcp_msg, int bcast_resp)
{
	int	magic_cookie = htonl (MAGIC_COOKIE);

	dhcp_msg->op		= DHCP_BOOTREQUEST;
	dhcp_msg->htype	= ARPHRD_ETHER;
	dhcp_msg->hlen		= ETH_ALEN;
	dhcp_msg->xid		= iface->xid;
	dhcp_msg->secs		= htons (10);

	if ( bcast_resp && iface->client_options->do_broadcast_response )
		dhcp_msg->flags = htons (BROADCAST_FLAG);

	memcpy (dhcp_msg->chaddr, iface->chaddr, ETH_ALEN);
	memcpy (dhcp_msg->options, &magic_cookie, 4);
}

/*****************************************************************************/
unsigned char *fill_host_and_class_id (dhcp_interface *iface, unsigned char *p)
{
	const char	*host_name = iface->client_options->host_name;
	int			 host_name_len = strlen (host_name);

	if ( host_name_len )
	{
		*p++ = hostName;
		*p++ = host_name_len;
		memcpy (p, host_name, host_name_len);
		p += host_name_len;
	}
	*p++ = dhcpClassIdentifier;
	*p++ = iface->cls_id_len;
	memcpy (p, iface->cls_id, iface->cls_id_len);
	p += iface->cls_id_len;
	memcpy (p, iface->cli_id, iface->cli_id_len);
	p += iface->cli_id_len;

	return p;
}

/*****************************************************************************/
unsigned char *fill_param_request (unsigned char *p)
{
	*p++ = dhcpParamRequest;
	*p++ = 14;
	*p++ = subnetMask;
	*p++ = routersOnSubnet;
	*p++ = dns;
	*p++ = hostName;
	*p++ = domainName;
	*p++ = rootPath;
	*p++ = defaultIPTTL;
	*p++ = broadcastAddr;
	*p++ = performMaskDiscovery;
	*p++ = performRouterDiscovery;
	*p++ = staticRoute;
	*p++ = nisDomainName;
	*p++ = nisServers;
	*p++ = ntpServers;
	return p;
}

/*****************************************************************************/
unsigned char *fill_requested_ipaddr (dhcp_interface *iface, unsigned char *p)
{
	*p++ = dhcpRequestedIPaddr;
	*p++ = 4;
	memcpy (p, &(iface->ciaddr), 4);
	p += 4; 
	return p;
}

/*****************************************************************************/
unsigned char *fill_lease_time (unsigned int *lease_time, unsigned char *p)
{
	*p++ = dhcpIPaddrLeaseTime;
	*p++ = 4;
	memcpy (p, lease_time, 4);
	p += 4;
	return p;
}

/*****************************************************************************/
unsigned char *fill_server_id (unsigned int *server_id, unsigned char *p)
{
	*p++ = dhcpServerIdentifier;
	*p++ = 4;
	memcpy (p, server_id, 4);
	p += 4;
	return p;
}

/*****************************************************************************/
unsigned char *fill_message_type (unsigned char request, unsigned char *p)
{
	const unsigned short dhcpMsgSize = htons (sizeof (dhcpMessage));

	*p++ = dhcpMessageType;
	*p++ = 1;
	*p++ = request;
	*p++ = dhcpMaxMsgSize;
	*p++ = 2;
	memcpy (p, &dhcpMsgSize, 2);
	p += 2;
	return p;
}
/*****************************************************************************/
void construct_dest_address (struct sockaddr_in *dest_addr, unsigned int in_addr)
{
	if (!dest_addr)
		return;

	memset (dest_addr, 0, sizeof (struct sockaddr_in));
	dest_addr->sin_family = AF_INET;
	dest_addr->sin_port = htons (DHCP_SERVER_PORT);
	memcpy (&dest_addr->sin_addr, &in_addr, sizeof (dest_addr->sin_addr));
}
/*****************************************************************************/
dhcpMessage *build_dhcp_discover (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;
	unsigned int			 lease_time = htonl (iface->default_lease_time);

	construct_dest_address (dest_addr, IP_BCAST_ADDR);

	fill_common_fields (iface, dhcp_msg, 1);
	p = fill_message_type (DHCP_DISCOVER, p);
	if ( iface->ciaddr )
	{
		if ( iface->client_options->do_rfc1541 )
			dhcp_msg->ciaddr = iface->ciaddr;
		else
			p = fill_requested_ipaddr (iface, p);
	}
	p = fill_lease_time (&lease_time, p);
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
dhcpMessage *build_dhcp_request (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, IP_BCAST_ADDR);
 
	fill_common_fields (iface, dhcp_msg, 1);
	p = fill_message_type (DHCP_REQUEST, p);
	p = fill_server_id (iface->dhcp_options.val[dhcpServerIdentifier], p);
	if ( iface->client_options->do_rfc1541 )
		dhcp_msg->ciaddr = iface->ciaddr;
	else
		p = fill_requested_ipaddr (iface, p);
	if ( iface->dhcp_options.val[dhcpIPaddrLeaseTime] )
		p = fill_lease_time (iface->dhcp_options.val[dhcpIPaddrLeaseTime], p);
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
dhcpMessage *build_dhcp_renew (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, iface->siaddr);

	fill_common_fields (iface, dhcp_msg, 1);
	dhcp_msg->ciaddr = iface->ciaddr;
	p = fill_message_type (DHCP_REQUEST, p);
#if 0
	if ( iface->dhcp_options.val[dhcpIPaddrLeaseTime] )
		p = fill_lease_time (iface->dhcp_options.val[dhcpIPaddrLeaseTime], p);
#endif
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
dhcpMessage *build_dhcp_rebind (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, IP_BCAST_ADDR);
 
	fill_common_fields (iface, dhcp_msg, 1);
	dhcp_msg->ciaddr = iface->ciaddr;
	p = fill_message_type (DHCP_REQUEST, p);
	if ( iface->dhcp_options.val[dhcpIPaddrLeaseTime] )
		p = fill_lease_time (iface->dhcp_options.val[dhcpIPaddrLeaseTime], p);
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
dhcpMessage *build_dhcp_reboot (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;
	unsigned int			 lease_time = htonl (iface->default_lease_time);

	construct_dest_address (dest_addr, IP_BCAST_ADDR);
 
	fill_common_fields (iface, dhcp_msg, 1);
	p = fill_message_type (DHCP_REQUEST, p);
	if ( iface->client_options->do_rfc1541 )
		dhcp_msg->ciaddr = iface->ciaddr;
	else
		p = fill_requested_ipaddr (iface, p);
	p = fill_lease_time (&lease_time, p);
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
dhcpMessage *build_dhcp_release (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, iface->siaddr);
 
	fill_common_fields (iface, dhcp_msg, 1);
	dhcp_msg->ciaddr = iface->ciaddr;
	*p++ = dhcpMessageType;
	*p++ = 1;
	*p++ = DHCP_RELEASE;
	p = fill_server_id (iface->dhcp_options.val[dhcpServerIdentifier], p);
	memcpy(p, iface->cli_id, iface->cli_id_len);
	p += iface->cli_id_len;
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
/*****************************************************************************/
#ifdef ARPCHECK
dhcpMessage *build_dhcp_decline (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, iface->siaddr);
 
	fill_common_fields (iface, udp_msg, 1);
	*p++ = dhcpMessageType;
	*p++ = 1;
	*p++ = DHCP_DECLINE;
	p = fill_server_id (iface->dhcp_options.val[dhcpServerIdentifier], p);
	if ( iface->client_options->do_rfc1541 )
		dhcp_msg->ciaddr = iface->ciaddr;
	else
		p = fill_requested_ipaddr (iface, p);
	memcpy (p, iface->cli_id, iface->cli_id_len);
	p += iface->cli_id_len;
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
#endif
/*****************************************************************************/
dhcpMessage *build_dhcp_inform (dhcp_interface *iface, int *msg_len, struct sockaddr_in *dest_addr)
{
	dhcpMessage			*dhcp_msg = calloc (1, sizeof (dhcpMessage));
	register unsigned char	*p = dhcp_msg->options + 4;

	construct_dest_address (dest_addr, IP_BCAST_ADDR);
 
	fill_common_fields (iface, dhcp_msg, 1);
	dhcp_msg->ciaddr = iface->ciaddr;
	p = fill_message_type (DHCP_INFORM, p);
	p = fill_param_request (p);
	p = fill_host_and_class_id (iface, p);
	*p = endOption;

	*msg_len = (char *)(++p) - (char *)dhcp_msg;
	return (dhcp_msg);
}
