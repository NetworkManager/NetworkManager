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


#define IPPACKET_SIZE	1500
#define MAGIC_COOKIE	0x63825363
#define BROADCAST_FLAG	0x8000
#define MAC_BCAST_ADDR	"\xff\xff\xff\xff\xff\xff"
#define IP_BCAST_ADDR	0xFFFFFFFF
#ifndef AF_PACKET
#define AF_PACKET		17	/* should have been in socketbits.h */
#endif
#define HWADDR_TRIES	3

/* UDP port numbers for DHCP */
#define DHCP_SERVER_PORT	67	/* from client to server */
#define DHCP_CLIENT_PORT	68	/* from server to client */

/* DHCP message OP code */
#define DHCP_BOOTREQUEST	1
#define DHCP_BOOTREPLY	2

/* DHCP message type */
#define DHCP_DISCOVER	1
#define DHCP_OFFER		2
#define DHCP_REQUEST	3
#define DHCP_DECLINE	4
#define DHCP_ACK		5
#define DHCP_NAK		6
#define DHCP_RELEASE	7
#define DHCP_INFORM		8
/* DHCP RETRANSMISSION TIMEOUT (seconds) */
#define DHCP_INITIAL_RTO	(5)
#define DHCP_MAX_RTO	(64)
#define DHCP_OPTIONS_LENGTH	312

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
	u_char	options[DHCP_OPTIONS_LENGTH];	/* message options */
} __attribute__((packed)) dhcpMessage;

typedef struct dhcpOptions
{
	u_char	len[256];
	void		*val[256];
	u_char	num;
} __attribute__((packed)) dhcpOptions;

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


typedef struct dhcp_interface
{
	char			*iface;
	int			 cease;
	int			 running;
	int			 sk;
	int			 foo_sk;
	short int		 saved_if_flags;
	unsigned int	 default_lease_time;
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
	const char		*name;
	const int			 len_hint;
	dhcp_option_type	 type;
} dhcp_option_table;

static dhcp_option_table	dhcp_opt_table[] = 
{
/* Names come from http://www.iana.org/assignments/bootp-dhcp-parameters, not to be changed */

/*   0 */	{ "Pad",							0, DHCP_OPT_INVALID },
/*   1 */	{ "Subnet Mask",					4, DHCP_OPT_ADDRESS },
/*   2 */	{ "Time Offset",					4, DHCP_OPT_TIME },
/*   3 */	{ "Router",						4, DHCP_OPT_ADDRESS },
/*   4 */	{ "Time Server",					4, DHCP_OPT_ADDRESS },
/*   5 */	{ "Name Server",					4, DHCP_OPT_ADDRESS },
/*   6 */	{ "Domain Server",					4, DHCP_OPT_ADDRESS },
/*   7 */	{ "Log Server",					4, DHCP_OPT_ADDRESS },
/*   8 */	{ "Quotes Server",					4, DHCP_OPT_ADDRESS },
/*   9 */	{ "LPR Server",					4, DHCP_OPT_ADDRESS },
/*  10 */	{ "Impress Server",					4, DHCP_OPT_ADDRESS },
/*  11 */	{ "RLP Server",					4, DHCP_OPT_ADDRESS },
/*  12 */	{ "Hostname",						1, DHCP_OPT_STRING },
/*  13 */	{ "Boot File Size",					2, DHCP_OPT_COUNT },
/*  14 */	{ "Merit Dump File",				1, DHCP_OPT_STRING },
/*  15 */	{ "Domain Name",					1, DHCP_OPT_STRING },
/*  16 */	{ "Swap Server",					1, DHCP_OPT_ADDRESS },
/*  17 */	{ "Root Path",						1, DHCP_OPT_STRING },
/*  18 */	{ "Extension Path",					1, DHCP_OPT_STRING },
/*  19 */	{ "Forward On/Off",					1, DHCP_OPT_TOGGLE },
/*  20 */	{ "SrcRte On/Off",					1, DHCP_OPT_TOGGLE },
/*  21 */	{ "Policy Filter",					1, DHCP_OPT_BLOB },
/*  22 */	{ "Max DG Assembly",				2, DHCP_OPT_COUNT },
/*  23 */	{ "Default IP TTL",					1, DHCP_OPT_COUNT },
/*  24 */	{ "MTU Timeout",					4, DHCP_OPT_TIME },
/*  25 */	{ "MTU Plateau",					1, DHCP_OPT_BLOB },
/*  26 */	{ "MTU Interface",					2, DHCP_OPT_COUNT },
/*  27 */	{ "MTU Subnet",					1, DHCP_OPT_TOGGLE },
/*  28 */	{ "Broadcast Address",				4, DHCP_OPT_ADDRESS },
/*  29 */	{ "Mask Discovery",					1, DHCP_OPT_TOGGLE },
/*  30 */	{ "Mask Supplier",					1, DHCP_OPT_TOGGLE },
/*  31 */	{ "Router Discovery",				1, DHCP_OPT_TOGGLE },
/*  32 */	{ "Router Request",					4, DHCP_OPT_ADDRESS },
/*  33 */	{ "Static Route",					1, DHCP_OPT_BLOB },
/*  34 */	{ "Trailers",						1, DHCP_OPT_TOGGLE },
/*  35 */	{ "ARP Timeout",					4, DHCP_OPT_TIME },
/*  36 */	{ "Ethernet",						1, DHCP_OPT_BLOB },
/*  37 */	{ "Default TCP TTL",				1, DHCP_OPT_COUNT},
/*  38 */	{ "Keepalive Time",					4, DHCP_OPT_TIME },
/*  39 */	{ "Keepalive Data",					1, DHCP_OPT_BLOB },
/*  40 */	{ "NIS Domain",					1, DHCP_OPT_STRING },
/*  41 */	{ "NIS Servers",					4, DHCP_OPT_ADDRESS },
/*  42 */	{ "NTP Servers",					4, DHCP_OPT_ADDRESS },
/*  43 */	{ "Vendor Specific",				1, DHCP_OPT_BLOB },
/*  44 */	{ "NETBIOS Name Srv",				4, DHCP_OPT_ADDRESS },
/*  45 */	{ "NETBIOS Dist Srv",				4, DHCP_OPT_ADDRESS },
/*  46 */	{ "NETBIOS Node Type",				1, DHCP_OPT_NUMBER },
/*  47 */	{ "NETBIOS Scope",					1, DHCP_OPT_NUMBER },
/*  48 */	{ "X Window Font",					4, DHCP_OPT_ADDRESS },
/*  49 */	{ "X Window Manager",				4, DHCP_OPT_ADDRESS },
/*  50 */	{ "Address Request",				4, DHCP_OPT_ADDRESS },
/*  51 */	{ "Address Time",					4, DHCP_OPT_TIME },
/*  52 */	{ "Overload",						1, DHCP_OPT_BLOB },
/*  53 */	{ "DHCP Msg Type",					1, DHCP_OPT_NUMBER },
/*  54 */	{ "DHCP Server Id",					4, DHCP_OPT_ADDRESS },
/*  55 */	{ "Parameter List",					1, DHCP_OPT_BLOB },
/*  56 */	{ "DHCP Message",					1, DHCP_OPT_BLOB },
/*  57 */	{ "DHCP Max Msg Size",				2, DHCP_OPT_COUNT },
/*  58 */	{ "Renewal Time",					4, DHCP_OPT_TIME },
/*  59 */	{ "Rebinding Time",					4, DHCP_OPT_TIME },
/*  60 */	{ "Class Id",						1, DHCP_OPT_BLOB },
/*  61 */	{ "Client Id",						1, DHCP_OPT_BLOB },
/*  62 */	{ "NetWare/IP Domain",				1, DHCP_OPT_STRING },
/*  63 */	{ "NetWare/IP Option",				1, DHCP_OPT_BLOB },
/*  64 */	{ "NIS-Domain-Name",				1, DHCP_OPT_STRING },
/*  65 */	{ "NIS-Server-Addr",				4, DHCP_OPT_ADDRESS },
/*  66 */	{ "Server-Name",					1, DHCP_OPT_STRING },
/*  67 */	{ "Bootfile-Name",					1, DHCP_OPT_STRING },
/*  68 */	{ "Home-Agent-Addrs",				4, DHCP_OPT_ADDRESS },
/*  69 */	{ "SMTP-Server",					4, DHCP_OPT_ADDRESS },
/*  70 */	{ "POP3-Server",					4, DHCP_OPT_ADDRESS },
/*  71 */	{ "NNTP-Server",					4, DHCP_OPT_ADDRESS },
/*  72 */	{ "WWW-Server",					4, DHCP_OPT_ADDRESS },
/*  73 */	{ "Finger-Server",					4, DHCP_OPT_ADDRESS },
/*  74 */	{ "IRC-Server",					4, DHCP_OPT_ADDRESS },
/*  75 */	{ "StreetTalk-Server",				4, DHCP_OPT_ADDRESS },
/*  76 */	{ "STDA-Server",					4, DHCP_OPT_ADDRESS },
/*  77 */	{ "User-Class",					1, DHCP_OPT_BLOB },
/*  78 */	{ "Directory Agent",				1, DHCP_OPT_BLOB },
/*  79 */	{ "Service Scope",					1, DHCP_OPT_BLOB },
/*  80 */	{ "Rapid Commit",					0, DHCP_OPT_BLOB },
/*  81 */	{ "Client FQDN",					1, DHCP_OPT_STRING },
/*  82 */	{ "Relay Agent Information",			1, DHCP_OPT_BLOB },
/*  83 */	{ "iSNS",							1, DHCP_OPT_BLOB },
/*  84 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  85 */	{ "NDS Servers",					4, DHCP_OPT_ADDRESS },
/*  86 */	{ "NDS Tree Name",					1, DHCP_OPT_BLOB },
/*  87 */	{ "NDS Context",					1, DHCP_OPT_BLOB },
/*  88 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  89 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  90 */	{ "Authentication",					1, DHCP_OPT_BLOB },
/*  91 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  92 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  93 */	{ "Client System",					1, DHCP_OPT_BLOB },
/*  94 */	{ "Client NDI",					1, DHCP_OPT_BLOB },
/*  95 */	{ "LDAP",							1, DHCP_OPT_BLOB },
/*  96 */	{ NULL,							0, DHCP_OPT_INVALID },
/*  97 */	{ "UUID/GUID",						1, DHCP_OPT_BLOB },
/*  98 */	{ "User-Auth",						1, DHCP_OPT_BLOB },
/*  99 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 100 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 101 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 102 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 103 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 104 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 105 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 106 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 107 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 108 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 109 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 110 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 111 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 112 */	{ "Netinfo Address",				1, DHCP_OPT_BLOB },
/* 113 */	{ "Netinfo Tag",					1, DHCP_OPT_BLOB },
/* 114 */	{ "URL",							1, DHCP_OPT_STRING },
/* 115 */	{ NULL,							1, DHCP_OPT_BLOB },
/* 116 */	{ "Auto-Config",					1, DHCP_OPT_BLOB },
/* 117 */	{ "Name Service Search",				1, DHCP_OPT_BLOB },
/* 118 */	{ "Subnet Selection Option",			4, DHCP_OPT_BLOB },
/* 119 */	{ "Domain Search",					1, DHCP_OPT_STRING },
/* 120 */	{ "SIP Servers DHCP Option",			1, DHCP_OPT_BLOB },
/* 121 */	{ "Classless Static Route Option",		1, DHCP_OPT_BLOB },
/* 122 */	{ "CCC",							1, DHCP_OPT_BLOB },
/* 123 */	{ "GeoConf Option",					16, DHCP_OPT_BLOB },
/* 124 */	{ "V-I Vendor Class",				1, DHCP_OPT_BLOB },
/* 125 */	{ "V-I Vendor-Specific Information",	1, DHCP_OPT_BLOB },
/* 126 */	{ NULL,							0, DHCP_OPT_INVALID },
/* 127 */	{ NULL,							0, DHCP_OPT_INVALID },
};
static const int dhcp_opt_table_len = sizeof(dhcp_opt_table)/sizeof(*dhcp_opt_table);

typedef udpipMessage *(*dhcp_msg_build_proc)(dhcp_interface *, int *msg_len);

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
