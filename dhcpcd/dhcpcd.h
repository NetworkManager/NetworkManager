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

/* DHCP option and value (cf. RFC1533) */
enum
{
	padOption					=	0,
	subnetMask				=	1,
	timerOffset				=	2,
	routersOnSubnet			=	3,
	timeServer				=	4,
	nameServer				=	5,
	dns						=	6,
	logServer					=	7,
	cookieServer				=	8,
	lprServer					=	9,
	impressServer				=	10,
	resourceLocationServer		=	11,
	hostName					=	12,
	bootFileSize				=	13,
	meritDumpFile				=	14,
	domainName				=	15,
	swapServer				=	16,
	rootPath					=	17,
	extentionsPath				=	18,
	IPforwarding				=	19,
	nonLocalSourceRouting		=	20,
	policyFilter				=	21,
	maxDgramReasmSize			=	22,
	defaultIPTTL				=	23,
	pathMTUagingTimeout			=	24,
	pathMTUplateauTable			=	25,
	ifMTU					=	26,
	allSubnetsLocal			=	27,
	broadcastAddr				=	28,
	performMaskDiscovery		=	29,
	maskSupplier				=	30,
	performRouterDiscovery		=	31,
	routerSolicitationAddr		=	32,
	staticRoute				=	33,
	trailerEncapsulation		=	34,
	arpCacheTimeout			=	35,
	ethernetEncapsulation		=	36,
	tcpDefaultTTL				=	37,
	tcpKeepaliveInterval		=	38,
	tcpKeepaliveGarbage			=	39,
	nisDomainName				=	40,
	nisServers				=	41,
	ntpServers				=	42,
	vendorSpecificInfo			=	43,
	netBIOSnameServer			=	44,
	netBIOSdgramDistServer		=	45,
	netBIOSnodeType			=	46,
	netBIOSscope				=	47,
	xFontServer				=	48,
	xDisplayManager			=	49,
	dhcpRequestedIPaddr			=	50,
	dhcpIPaddrLeaseTime			=	51,
	dhcpOptionOverload			=	52,
	dhcpMessageType			=	53,
	dhcpServerIdentifier		=	54,
	dhcpParamRequest			=	55,
	dhcpMsg					=	56,
	dhcpMaxMsgSize				=	57,
	dhcpT1value				=	58,
	dhcpT2value				=	59,
	dhcpClassIdentifier			=	60,
	dhcpClientIdentifier		=	61,
	endOption					=	255
};

typedef enum dhcp_option_type
{
	DHCP_OPT_INVALID,
	DHCP_OPT_ADDRESS,
	DHCP_OPT_TIME,
	DHCP_OPT_STRING,
	DHCP_OPT_COUNT,
	DHCP_OPT_TOGGLE,
	DHCP_OPT_BLOB,
	DHCP_OPT_NUMBER,
} dhcp_option_type;

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

struct dhcp_interface	*dhcp_interface_init		(const char *if_name, dhcp_client_options *in_opts);
void					 dhcp_interface_free		(struct dhcp_interface *iface);
void					 dhcp_interface_cease		(struct dhcp_interface *iface);

int				 dhcp_interface_option_present	(struct dhcp_interface *iface, int val);
int				 dhcp_interface_option_len		(struct dhcp_interface *iface, int val);
void				*dhcp_interface_option_payload	(struct dhcp_interface *iface, int val);
int				 dhcp_option_record_len			(int val);
dhcp_option_type	 dhcp_option_record_type			(int val);
int				 dhcp_option_id_by_name			(const char *name);
const char *		 dhcp_option_name				(int val);

#endif
