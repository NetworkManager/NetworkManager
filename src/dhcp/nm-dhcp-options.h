/*
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
 * (C) Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_DHCP_OPTIONS_H__
#define __NM_DHCP_OPTIONS_H__

typedef enum {
	NM_DHCP_OPTION_DHCP4_PAD                            = 0,
	NM_DHCP_OPTION_DHCP4_SUBNET_MASK                    = 1,
	NM_DHCP_OPTION_DHCP4_TIME_OFFSET                    = 2,
	NM_DHCP_OPTION_DHCP4_ROUTER                         = 3,
	NM_DHCP_OPTION_DHCP4_TIME_SERVERS                   = 4,
	NM_DHCP_OPTION_DHCP4_IEN116_NAME_SERVERS            = 5,
	NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER             = 6,
	NM_DHCP_OPTION_DHCP4_LOG_SERVERS                    = 7,
	NM_DHCP_OPTION_DHCP4_COOKIE_SERVERS                 = 8,
	NM_DHCP_OPTION_DHCP4_LPR_SERVERS                    = 9,
	NM_DHCP_OPTION_DHCP4_IMPRESS_SERVERS                = 10,
	NM_DHCP_OPTION_DHCP4_RESOURCE_LOCATION_SERVERS      = 11,
	NM_DHCP_OPTION_DHCP4_HOST_NAME                      = 12,
	NM_DHCP_OPTION_DHCP4_BOOT_FILE_SIZE                 = 13,
	NM_DHCP_OPTION_DHCP4_MERIT_DUMP                     = 14,
	NM_DHCP_OPTION_DHCP4_DOMAIN_NAME                    = 15,
	NM_DHCP_OPTION_DHCP4_SWAP_SERVER                    = 16,
	NM_DHCP_OPTION_DHCP4_ROOT_PATH                      = 17,
	NM_DHCP_OPTION_DHCP4_EXTENSIONS_PATH                = 18,
	NM_DHCP_OPTION_DHCP4_ENABLE_IP_FORWARDING           = 19,
	NM_DHCP_OPTION_DHCP4_ENABLE_SRC_ROUTING             = 20,
	NM_DHCP_OPTION_DHCP4_POLICY_FILTER                  = 21,
	NM_DHCP_OPTION_DHCP4_INTERFACE_MDR                  = 22,
	NM_DHCP_OPTION_DHCP4_INTERFACE_TTL                  = 23,
	NM_DHCP_OPTION_DHCP4_INTERFACE_MTU_AGING_TIMEOUT    = 24,
	NM_DHCP_OPTION_DHCP4_PATH_MTU_PLATEAU_TABLE         = 25,
	NM_DHCP_OPTION_DHCP4_INTERFACE_MTU                  = 26,
	NM_DHCP_OPTION_DHCP4_ALL_SUBNETS_LOCAL              = 27,
	NM_DHCP_OPTION_DHCP4_BROADCAST                      = 28,
	NM_DHCP_OPTION_DHCP4_PERFORM_MASK_DISCOVERY         = 29,
	NM_DHCP_OPTION_DHCP4_MASK_SUPPLIER                  = 30,
	NM_DHCP_OPTION_DHCP4_ROUTER_DISCOVERY               = 31,
	NM_DHCP_OPTION_DHCP4_ROUTER_SOLICITATION_ADDR       = 32,
	NM_DHCP_OPTION_DHCP4_STATIC_ROUTE                   = 33,
	NM_DHCP_OPTION_DHCP4_TRAILER_ENCAPSULATION          = 34,
	NM_DHCP_OPTION_DHCP4_ARP_CACHE_TIMEOUT              = 35,
	NM_DHCP_OPTION_DHCP4_IEEE802_3_ENCAPSULATION        = 36,
	NM_DHCP_OPTION_DHCP4_DEFAULT_TCP_TTL                = 37,
	NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_INTERVAL         = 38,
	NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_GARBAGE          = 39,
	NM_DHCP_OPTION_DHCP4_NIS_DOMAIN                     = 40,
	NM_DHCP_OPTION_DHCP4_NIS_SERVERS                    = 41,
	NM_DHCP_OPTION_DHCP4_NTP_SERVER                     = 42,
	NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC                = 43,
	NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER             = 44,
	NM_DHCP_OPTION_DHCP4_NETBIOS_DD_SERVER              = 45,
	NM_DHCP_OPTION_DHCP4_FONT_SERVERS                   = 48,
	NM_DHCP_OPTION_DHCP4_X_DISPLAY_MANAGER              = 49,
	NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME          = 51,
	NM_DHCP_OPTION_DHCP4_SERVER_ID                      = 54,
	NM_DHCP_OPTION_DHCP4_RENEWAL_T1_TIME                = 58,
	NM_DHCP_OPTION_DHCP4_REBINDING_T2_TIME              = 59,
	NM_DHCP_OPTION_DHCP4_CLIENT_ID                      = 61,
	NM_DHCP_OPTION_DHCP4_NWIP_DOMAIN                    = 62,
	NM_DHCP_OPTION_DHCP4_NWIP_SUBOPTIONS                = 63,
	NM_DHCP_OPTION_DHCP4_NISPLUS_DOMAIN                 = 64,
	NM_DHCP_OPTION_DHCP4_NISPLUS_SERVERS                = 65,
	NM_DHCP_OPTION_DHCP4_TFTP_SERVER_NAME               = 66,
	NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME                  = 67,
	NM_DHCP_OPTION_DHCP4_MOBILE_IP_HOME_AGENT           = 68,
	NM_DHCP_OPTION_DHCP4_SMTP_SERVER                    = 69,
	NM_DHCP_OPTION_DHCP4_POP_SERVER                     = 70,
	NM_DHCP_OPTION_DHCP4_NNTP_SERVER                    = 71,
	NM_DHCP_OPTION_DHCP4_WWW_SERVER                     = 72,
	NM_DHCP_OPTION_DHCP4_FINGER_SERVER                  = 73,
	NM_DHCP_OPTION_DHCP4_IRC_SERVER                     = 74,
	NM_DHCP_OPTION_DHCP4_STREETTALK_SERVER              = 75,
	NM_DHCP_OPTION_DHCP4_STREETTALK_DIR_ASSIST_SERVER   = 76,
	NM_DHCP_OPTION_DHCP4_SLP_DIRECTORY_AGENT            = 78,
	NM_DHCP_OPTION_DHCP4_SLP_SERVICE_SCOPE              = 79,
	NM_DHCP_OPTION_DHCP4_CLIENT_FQDN                    = 81,
	NM_DHCP_OPTION_DHCP4_RELAY_AGENT_INFORMATION        = 82,
	NM_DHCP_OPTION_DHCP4_NDS_SERVERS                    = 85,
	NM_DHCP_OPTION_DHCP4_NDS_TREE_NAME                  = 86,
	NM_DHCP_OPTION_DHCP4_NDS_CONTEXT                    = 87,
	NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_NAMES          = 88,
	NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_ADDRESS        = 89,
	NM_DHCP_OPTION_DHCP4_CLIENT_LAST_TRANSACTION        = 91,
	NM_DHCP_OPTION_DHCP4_ASSOCIATED_IP                  = 92,
	NM_DHCP_OPTION_DHCP4_PXE_SYSTEM_TYPE                = 93,
	NM_DHCP_OPTION_DHCP4_PXE_INTERFACE_ID               = 94,
	NM_DHCP_OPTION_DHCP4_PXE_CLIENT_ID                  = 97,
	NM_DHCP_OPTION_DHCP4_UAP_SERVERS                    = 98,
	NM_DHCP_OPTION_DHCP4_GEOCONF_CIVIC                  = 99,
	NM_DHCP_OPTION_DHCP4_NEW_TZDB_TIMEZONE              = 101,
	NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_ADDRESS         = 112,
	NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_TAG             = 113,
	NM_DHCP_OPTION_DHCP4_DEFAULT_URL                    = 114,
	NM_DHCP_OPTION_DHCP4_AUTO_CONFIG                    = 116,
	NM_DHCP_OPTION_DHCP4_NAME_SERVICE_SEARCH            = 117,
	NM_DHCP_OPTION_DHCP4_SUBNET_SELECTION               = 118,
	NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST             = 119,
	NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE         = 121,
	NM_DHCP_OPTION_DHCP4_VIVCO                          = 124,
	NM_DHCP_OPTION_DHCP4_VIVSO                          = 125,
	NM_DHCP_OPTION_DHCP4_PANA_AGENT                     = 136,
	NM_DHCP_OPTION_DHCP4_V4_LOST                        = 137,
	NM_DHCP_OPTION_DHCP4_SIP_UA_CS_DOMAINS              = 141,
	NM_DHCP_OPTION_DHCP4_IPV4_ADDRESS_ANDSF             = 142,
	NM_DHCP_OPTION_DHCP4_RDNSS_SELECTION                = 146,
	NM_DHCP_OPTION_DHCP4_TFTP_SERVER_ADDRESS            = 150,
	NM_DHCP_OPTION_DHCP4_V4_PORTPARAMS                  = 159,
	NM_DHCP_OPTION_DHCP4_V4_CAPTIVE_PORTAL              = 160,
	NM_DHCP_OPTION_DHCP4_LOADER_CONFIGFILE              = 209,
	NM_DHCP_OPTION_DHCP4_LOADER_PATHPREFIX              = 210,
	NM_DHCP_OPTION_DHCP4_LOADER_REBOOTTIME              = 211,
	NM_DHCP_OPTION_DHCP4_OPTION_6RD                     = 212,
	NM_DHCP_OPTION_DHCP4_V4_ACCESS_DOMAIN               = 213,
	NM_DHCP_OPTION_DHCP4_PRIVATE_224                    = 224,
	NM_DHCP_OPTION_DHCP4_PRIVATE_225                    = 225,
	NM_DHCP_OPTION_DHCP4_PRIVATE_226                    = 226,
	NM_DHCP_OPTION_DHCP4_PRIVATE_227                    = 227,
	NM_DHCP_OPTION_DHCP4_PRIVATE_228                    = 228,
	NM_DHCP_OPTION_DHCP4_PRIVATE_229                    = 229,
	NM_DHCP_OPTION_DHCP4_PRIVATE_230                    = 230,
	NM_DHCP_OPTION_DHCP4_PRIVATE_231                    = 231,
	NM_DHCP_OPTION_DHCP4_PRIVATE_232                    = 232,
	NM_DHCP_OPTION_DHCP4_PRIVATE_233                    = 233,
	NM_DHCP_OPTION_DHCP4_PRIVATE_234                    = 234,
	NM_DHCP_OPTION_DHCP4_PRIVATE_235                    = 235,
	NM_DHCP_OPTION_DHCP4_PRIVATE_236                    = 236,
	NM_DHCP_OPTION_DHCP4_PRIVATE_237                    = 237,
	NM_DHCP_OPTION_DHCP4_PRIVATE_238                    = 238,
	NM_DHCP_OPTION_DHCP4_PRIVATE_239                    = 239,
	NM_DHCP_OPTION_DHCP4_PRIVATE_240                    = 240,
	NM_DHCP_OPTION_DHCP4_PRIVATE_241                    = 241,
	NM_DHCP_OPTION_DHCP4_PRIVATE_242                    = 242,
	NM_DHCP_OPTION_DHCP4_PRIVATE_243                    = 243,
	NM_DHCP_OPTION_DHCP4_PRIVATE_244                    = 244,
	NM_DHCP_OPTION_DHCP4_PRIVATE_245                    = 245,
	NM_DHCP_OPTION_DHCP4_PRIVATE_246                    = 246,
	NM_DHCP_OPTION_DHCP4_PRIVATE_247                    = 247,
	NM_DHCP_OPTION_DHCP4_PRIVATE_248                    = 248,
	NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE = 249,
	NM_DHCP_OPTION_DHCP4_PRIVATE_250                    = 250,
	NM_DHCP_OPTION_DHCP4_PRIVATE_251                    = 251,
	NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY    = 252,
	NM_DHCP_OPTION_DHCP4_PRIVATE_253                    = 253,
	NM_DHCP_OPTION_DHCP4_PRIVATE_254                    = 254,
	NM_DHCP_OPTION_DHCP4_END                            = 255,
	/* Internal values */
	NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS                  = 1024,
	NM_DHCP_OPTION_DHCP4_NM_EXPIRY                      = 1025,
} NMDhcpOptionDhcp4Options;

typedef enum {
	NM_DHCP_OPTION_DHCP6_CLIENTID          = 1,
	NM_DHCP_OPTION_DHCP6_SERVERID          = 2,
	NM_DHCP_OPTION_DHCP6_DNS_SERVERS       = 23,
	NM_DHCP_OPTION_DHCP6_DOMAIN_LIST       = 24,
	NM_DHCP_OPTION_DHCP6_SNTP_SERVERS      = 31,
	/* Internal values */
	NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS     = 1026,
	NM_DHCP_OPTION_DHCP6_NM_PREFIXLEN      = 1027,
	NM_DHCP_OPTION_DHCP6_NM_PREFERRED_LIFE = 1028,
	NM_DHCP_OPTION_DHCP6_NM_MAX_LIFE       = 1029,
	NM_DHCP_OPTION_DHCP6_NM_STARTS         = 1030,
	NM_DHCP_OPTION_DHCP6_NM_LIFE_STARTS    = 1031,
	NM_DHCP_OPTION_DHCP6_NM_RENEW          = 1032,
	NM_DHCP_OPTION_DHCP6_NM_REBIND         = 1033,
	NM_DHCP_OPTION_DHCP6_NM_IAID           = 1034,

} NMDhcpOptionDhcp6Options;

typedef struct {
	const char *name;
	uint16_t option_num;
	bool include;
} NMDhcpOption;

extern const NMDhcpOption _nm_dhcp_option_dhcp4_options[];
extern const NMDhcpOption _nm_dhcp_option_dhcp6_options[];

const char *nm_dhcp_option_request_string (const NMDhcpOption *requests, guint option);
void nm_dhcp_option_take_option (GHashTable *options, const NMDhcpOption *requests, guint option, char *value);
void nm_dhcp_option_add_option (GHashTable *options, const NMDhcpOption *requests, guint option, const char *value);
void nm_dhcp_option_add_option_u64 (GHashTable *options, const NMDhcpOption *requests, guint option, guint64 value);
void nm_dhcp_option_add_requests_to_options (GHashTable *options, const NMDhcpOption *requests);
GHashTable *nm_dhcp_option_create_options_dict (void);

#endif /* __NM_DHCP_OPTIONS_H__ */
