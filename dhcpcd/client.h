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

#ifndef CLIENT_H
#define CLIENT_H

#include <net/ethernet.h>
#include <linux/types.h>
#include <linux/if_tr.h>
#include <netinet/in.h>
#include "dhcpcd.h"


#define IPPACKET_SIZE		1500
#define MAGIC_COOKIE		0x63825363
#define BROADCAST_FLAG		0x8000
#define MAC_BCAST_ADDR		"\xff\xff\xff\xff\xff\xff"
#ifndef AF_PACKET
#define AF_PACKET		17	/* should have been in socketbits.h */
#endif
#define HWADDR_TRIES		3

/* UDP port numbers for DHCP */
#define	DHCP_SERVER_PORT	67	/* from client to server */
#define DHCP_CLIENT_PORT	68	/* from server to client */

/* DHCP message OP code */
#define DHCP_BOOTREQUEST	1
#define DHCP_BOOTREPLY		2

/* DHCP message type */
#define	DHCP_DISCOVER		1
#define DHCP_OFFER		2
#define	DHCP_REQUEST		3
#define	DHCP_DECLINE		4
#define	DHCP_ACK		5
#define DHCP_NAK		6
#define	DHCP_RELEASE		7
#define DHCP_INFORM		8
/* DHCP RETRANSMISSION TIMEOUT (microseconds) */
#define DHCP_INITIAL_RTO	(4*1000000)
#define DHCP_MAX_RTO		(64*1000000)

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

typedef struct dhcpMessage
{
	u_char	op;			/* message type */
	u_char	htype;		/* hardware address type */
	u_char	hlen;		/* hardware address length */
	u_char	hops;		/* should be zero in client's message */
	u_int	xid;			/* transaction id */
	u_short	secs;		/* elapsed time in sec. from trying to boot */
	u_short	flags;
	u_int	ciaddr;		/* (previously allocated) client IP address */
	u_int	yiaddr;		/* 'your' client IP address */
	u_int	siaddr;		/* should be zero in client's messages */
	u_int	giaddr;		/* should be zero in client's messages */
	u_char	chaddr[16];	/* client's hardware address */
	u_char	sname[64];	/* server host name, null terminated string */
	u_char	file[128];	/* boot file name, null terminated string */
	u_char	options[312];	/* message options */
} __attribute__((packed)) dhcpMessage;

struct packed_ether_header
{
	u_int8_t	ether_dhost[ETH_ALEN];      /* destination eth addr */
	u_int8_t	ether_shost[ETH_ALEN];      /* source ether addr    */
	u_int16_t	ether_type;                 /* packet type ID field */
} __attribute__((packed));

#define TOKEN_RING_HEADER_PAD		sizeof(struct trh_hdr) + sizeof(struct trllc)
typedef struct udpipMessage
{
	struct packed_ether_header	ethhdr;
	char						udpipmsg[IPPACKET_SIZE];
	char						pad_for_tokenring_header[TOKEN_RING_HEADER_PAD];
} __attribute__((packed)) udpipMessage;

typedef struct dhcpOptions
{
	u_char	num;
	u_char	len[256];
	void		*val[256];
} __attribute__((packed)) dhcpOptions;


typedef struct dhcp_interface
{
	char			*iface;
	int			 cease;
	int			 running;
	int			 sk;
	int			 foo_sk;
	short int		 saved_if_flags;
	int			 bTokenRing;
	unsigned int	 default_lease_time;
	time_t		 req_sent_time;
	struct in_addr	 default_router;

	int			ciaddr;
	unsigned char	chaddr[ETH_ALEN];
	int			siaddr;
	unsigned char	shaddr[ETH_ALEN];
	unsigned int	xid;
	unsigned short	ip_id;
	unsigned char	cls_id[DHCP_CLASS_ID_MAX_LEN];
	int			cls_id_len;
	unsigned char	cli_id[DHCP_CLIENT_ID_MAX_LEN];
	int			cli_id_len;
	dhcpOptions	dhcp_options;

	dhcp_client_options	*client_options;
} dhcp_interface;

typedef struct dhcp_option_table
{
	const int		 option;
	const char	*name;
	const int		 len;
} dhcp_option_table;

static dhcp_option_table	dhcp_opt_table[] = 
{
	{ padOption,			"padOption",			1  },
	{ subnetMask,			"subnetMask",			4  },
	{ timerOffset,			"timerOffset", 		-1 },
	{ routersOnSubnet,		"routersOnSubnet",		4  },
	{ timeServer,			"timeServer",			4  },
	{ nameServer,			"nameServer",			4  },
	{ dns,				"dns",				4  },
	{ logServer,			"logServer",			4  },
	{ cookieServer,		"cookieServer",		4  },
	{ lprServer,			"lprServer",			4  },
	{ impressServer,		"impressServer",		4  },
	{ resourceLocationServer,"resourceLocationServer",4  },
	{ hostName,			"hostName",			-1 },
	{ bootFileSize,		"bootFileSize",		4  },
	{ meritDumpFile,		"meritDumpFile",		4  },
	{ domainName,			"domainName",			-1 },
	{ swapServer,			"swapServer",			4  },
	{ rootPath,			"rootPath",			-1 },
	{ extentionsPath,		"extentionsPath",		-1 },
	{ IPforwarding,		"IPforwarding",		-1 },
	{ nonLocalSourceRouting,	"nonLocalSourceRouting",	-1 },
	{ policyFilter,		"policyFilter",		-1 },
	{ maxDgramReasmSize,	"maxDgramReasmSize",	-1 },
	{ defaultIPTTL,		"defaultIPTTL",		-1 },
	{ pathMTUagingTimeout,	"pathMTUagingTimeout",	-1 },
	{ pathMTUplateauTable,	"pathMTUplateauTable",	-1 },
	{ ifMTU,				"ifMTU",				-1 },
	{ allSubnetsLocal,		"allSubnetsLocal",		-1 },
	{ broadcastAddr,		"broadcastAddr",		4  },
	{ performMaskDiscovery,	"performMaskDiscovery",	-1 },
	{ routerSolicitationAddr,"routerSolicitationAddr",-1 },
	{ staticRoute,			"staticRoute",			4  },
	{ trailerEncapsulation,	"trailerEncapsulation",	-1 },
	{ arpCacheTimeout,		"arpCacheTimeout",		-1 },
	{ ethernetEncapsulation,	"ethernetEncapsulation",	-1 },
	{ tcpDefaultTTL,		"tcpDefaultTTL",		-1 },
	{ tcpKeepaliveInterval,	"tcpKeepaliveInterval",	-1 },
	{ tcpKeepaliveGarbage,	"tcpKeepaliveGarbage",	-1 },
	{ nisDomainName,		"nisDomainName",		-1 },
	{ nisServers,			"nisServers",			4  },
	{ ntpServers,			"ntpServers",			4  },
	{ vendorSpecificInfo,	"vendorSpecificInfo",	-1 },
	{ netBIOSnameServer,	"netBIOSnameServer",	-1 },
	{ netBIOSdgramDistServer,"netBIOSdgramDistServer",-1 },
	{ netBIOSnodeType,		"netBIOSnodeType",		-1 },
	{ netBIOSscope,		"netBIOSscope",		-1 },
	{ xFontServer,			"xFontServer",			-1 },
	{ xDisplayManager,		"xDisplayManager",		-1 },
	{ dhcpRequestedIPaddr,	"dhcpRequestedIPaddr",	4  },
	{ dhcpIPaddrLeaseTime,	"dhcpIPaddrLeaseTime",	4  },
	{ dhcpOptionOverload,	"dhcpOptionOverload",	-1 },
	{ dhcpMessageType,		"dhcpMessageType",		-1 },
	{ dhcpServerIdentifier,	"dhcpServerIdentifier",	-1 },
	{ dhcpParamRequest,		"dhcpParamRequest",		-1 },
	{ dhcpMsg,			"dhcpMsg",			-1 },
	{ dhcpMaxMsgSize,		"dhcpMaxMsgSize",		-1 },
	{ dhcpT1value,			"dhcpT1value",			4  },
	{ dhcpT2value,			"dhcpT2value",			4  },
	{ dhcpClassIdentifier,	"dhcpClassIdentifier",	-1 },
	{ dhcpClientIdentifier,	"dhcpClientIdentifier",	-1 },
	{ -1,				NULL,				-1 }
};

typedef udpipMessage *(*dhcp_msg_build_proc)(dhcp_interface *);

int dhcp_reboot(dhcp_interface *iface);
int dhcp_init(dhcp_interface *iface);
int dhcp_request(dhcp_interface *iface, dhcp_msg_build_proc buildDhcpMsg);
int dhcp_renew(dhcp_interface *iface);
int dhcp_rebind(dhcp_interface *iface);
int dhcp_release(dhcp_interface *iface);
#ifdef ARPCHECK
int dhcp_decline(dhcp_interface *iface);
#endif
int dhcp_inform(dhcp_interface *iface);

#endif
