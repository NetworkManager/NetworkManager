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

#include "nm-default.h"

#include "nm-dhcp-options.h"


#define REQPREFIX "requested_"

#define REQ(_num, _name, _include) \
	{ \
		.name = REQPREFIX""_name, \
		.option_num = _num, \
		.include = _include, \
	}

const NMDhcpOption _nm_dhcp_option_dhcp4_options[] = {
	REQ (NM_DHCP_OPTION_DHCP4_SUBNET_MASK,                       "subnet_mask",                     TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_TIME_OFFSET,                       "time_offset",                     TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER,                "domain_name_servers",             TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_HOST_NAME,                         "host_name",                       TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_DOMAIN_NAME,                       "domain_name",                     TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_INTERFACE_MTU,                     "interface_mtu",                   TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_BROADCAST,                         "broadcast_address",               TRUE ),
	/* RFC 3442: The Classless Static Routes option code MUST appear in the parameter
	 *   request list prior to both the Router option code and the Static
	 *   Routes option code, if present. */
	REQ (NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE,            "rfc3442_classless_static_routes", TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_ROUTER,                            "routers",                         TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_STATIC_ROUTE,                      "static_routes",                   TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_NIS_DOMAIN,                        "nis_domain",                      TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_NIS_SERVERS,                       "nis_servers",                     TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_NTP_SERVER,                        "ntp_servers",                     TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_SERVER_ID,                         "dhcp_server_identifier",          TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST,                "domain_search",                   TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE,    "ms_classless_static_routes",      TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY,       "wpad",                            TRUE ),
	REQ (NM_DHCP_OPTION_DHCP4_ROOT_PATH,                         "root_path",                       TRUE ),

	REQ (NM_DHCP_OPTION_DHCP4_TIME_SERVERS,                      "time_servers",                    FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IEN116_NAME_SERVERS,               "ien116_name_servers",             FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_LOG_SERVERS,                       "log_servers",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_COOKIE_SERVERS,                    "cookie_servers",                  FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_LPR_SERVERS,                       "lpr_servers",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IMPRESS_SERVERS,                   "impress_servers",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_RESOURCE_LOCATION_SERVERS,         "resource_location_servers",       FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_BOOT_FILE_SIZE,                    "boot_size",                       FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_MERIT_DUMP,                        "merit_dump",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SWAP_SERVER,                       "swap_server",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_EXTENSIONS_PATH,                   "extensions_path",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ENABLE_IP_FORWARDING,              "ip_forwarding",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ENABLE_SRC_ROUTING,                "non_local_source_routing",        FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_POLICY_FILTER,                     "policy_filter",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_INTERFACE_MDR,                     "max_dgram_reassembly",            FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_INTERFACE_TTL,                     "default_ip_ttl",                  FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_INTERFACE_MTU_AGING_TIMEOUT,       "path_mtu_aging_timeout",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PATH_MTU_PLATEAU_TABLE,            "path_mtu_plateau_table",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ALL_SUBNETS_LOCAL,                 "all_subnets_local",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PERFORM_MASK_DISCOVERY,            "perform_mask_discovery",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_MASK_SUPPLIER,                     "mask_supplier",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ROUTER_DISCOVERY,                  "router_discovery",                FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ROUTER_SOLICITATION_ADDR,          "router_solicitation_address",     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_TRAILER_ENCAPSULATION,             "trailer_encapsulation",           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ARP_CACHE_TIMEOUT,                 "arp_cache_timeout",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IEEE802_3_ENCAPSULATION,           "ieee802_3_encapsulation",         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_DEFAULT_TCP_TTL,                   "default_tcp_ttl",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_INTERVAL,            "tcp_keepalive_internal",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_GARBAGE,             "tcp_keepalive_garbage",           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC,                   "vendor_encapsulated_options",     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER,                "netbios_name_servers",            FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NETBIOS_DD_SERVER,                 "netbios_dd_server",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_FONT_SERVERS,                      "font_servers",                    FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_X_DISPLAY_MANAGER,                 "x_display_manager",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME,             "dhcp_lease_time",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_RENEWAL_T1_TIME,                   "dhcp_renewal_time",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_REBINDING_T2_TIME,                 "dhcp_rebinding_time",             FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_CLIENT_ID,                         "dhcp_client_identifier",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NEW_TZDB_TIMEZONE,                 "tcode",                           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NWIP_DOMAIN,                       "nwip_domain",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NWIP_SUBOPTIONS,                   "nwip_suboptions",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NISPLUS_DOMAIN,                    "nisplus_domain",                  FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NISPLUS_SERVERS,                   "nisplus_servers",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_TFTP_SERVER_NAME,                  "tftp_server_name",                FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME,                     "bootfile_name",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_MOBILE_IP_HOME_AGENT,              "mobile_ip_home_agent",            FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SMTP_SERVER,                       "smtp_server",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_POP_SERVER,                        "pop_server",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NNTP_SERVER,                       "nntp_server",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_WWW_SERVER,                        "www_server",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_FINGER_SERVER,                     "finger_server",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IRC_SERVER,                        "irc_server",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_STREETTALK_SERVER,                 "streettalk_server",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_STREETTALK_DIR_ASSIST_SERVER,      "streettalk_directory_assistance_server", FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SLP_DIRECTORY_AGENT,               "slp_directory_agent",             FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SLP_SERVICE_SCOPE,                 "slp_service_scope",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_CLIENT_FQDN,                       "fqdn",                            FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_RELAY_AGENT_INFORMATION,           "relay_agent_information",         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NDS_SERVERS,                       "nds_servers",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NDS_TREE_NAME,                     "nds_tree_name",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NDS_CONTEXT,                       "nds_context",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_NAMES,             "bcms_controller_names",           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_ADDRESS,           "bcms_controller_address",         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_CLIENT_LAST_TRANSACTION,           "client_last_transaction_time",    FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_ASSOCIATED_IP,                     "associated_ip",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PXE_SYSTEM_TYPE,                   "pxe_system_type",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PXE_INTERFACE_ID,                  "pxe_interface_id",                FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PXE_CLIENT_ID,                     "pxe_client_id",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_UAP_SERVERS,                       "uap_servers",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_GEOCONF_CIVIC,                     "geoconf_civic",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_ADDRESS,            "netinfo_server_address",          FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_TAG,                "netinfo_server_tag",              FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_DEFAULT_URL,                       "default_url",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_AUTO_CONFIG,                       "auto_config",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NAME_SERVICE_SEARCH,               "name_service_search",             FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SUBNET_SELECTION,                  "subnet_selection",                FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_VIVCO,                             "vivco",                           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_VIVSO,                             "vivso",                           FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PANA_AGENT,                        "pana_agent",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_V4_LOST,                           "v4_lost",                         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_SIP_UA_CS_DOMAINS,                 "sip_ua_cs_domains",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_IPV4_ADDRESS_ANDSF,                "ipv4_address_andsf",              FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_RDNSS_SELECTION,                   "rndss_selection",                 FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_TFTP_SERVER_ADDRESS,               "tftp_server_address",             FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_V4_PORTPARAMS,                     "v4_portparams",                   FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_V4_CAPTIVE_PORTAL,                 "v4_captive_portal",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_LOADER_CONFIGFILE,                 "loader_configfile",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_LOADER_PATHPREFIX,                 "loader_pathprefix",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_LOADER_REBOOTTIME,                 "loader_reboottime",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_OPTION_6RD,                        "option_6rd",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_V4_ACCESS_DOMAIN,                  "v4_access_domain",                FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_224,                       "private_224",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_225,                       "private_225",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_226,                       "private_226",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_227,                       "private_227",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_228,                       "private_228",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_229,                       "private_229",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_230,                       "private_230",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_231,                       "private_231",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_232,                       "private_232",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_233,                       "private_233",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_234,                       "private_234",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_235,                       "private_235",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_236,                       "private_236",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_237,                       "private_237",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_238,                       "private_238",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_239,                       "private_239",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_240,                       "private_240",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_241,                       "private_241",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_242,                       "private_242",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_243,                       "private_243",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_244,                       "private_244",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_245,                       "private_245",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_246,                       "private_246",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_247,                       "private_247",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_248,                       "private_248",                     FALSE ),
	/* NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE */
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_250,                       "private_250",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_251,                       "private_251",                     FALSE ),
	/* NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY */
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_253,                       "private_253",                     FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_PRIVATE_254,                       "private_254",                     FALSE ),

	/* Internal values */
	REQ (NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS,                     "ip_address",                      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP4_NM_EXPIRY,                         "expiry",                          FALSE ),

	{ 0 }
};

const NMDhcpOption _nm_dhcp_option_dhcp6_options[] = {
	REQ (NM_DHCP_OPTION_DHCP6_CLIENTID,                         "dhcp6_client_id",     FALSE ),

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	REQ (NM_DHCP_OPTION_DHCP6_SERVERID,                         "dhcp6_server_id",     FALSE ),

	REQ (NM_DHCP_OPTION_DHCP6_DNS_SERVERS,                      "dhcp6_name_servers",  TRUE ),
	REQ (NM_DHCP_OPTION_DHCP6_DOMAIN_LIST,                      "dhcp6_domain_search", TRUE ),
	REQ (NM_DHCP_OPTION_DHCP6_SNTP_SERVERS,                     "dhcp6_sntp_servers",  TRUE ),

	/* Internal values */
	REQ (NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS,                    "ip6_address",         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_PREFIXLEN,                     "ip6_prefixlen",       FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_PREFERRED_LIFE,                "preferred_life",      FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_MAX_LIFE,                      "max_life",            FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_STARTS,                        "starts",              FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_LIFE_STARTS,                   "life_starts",         FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_RENEW,                         "renew",               FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_REBIND,                        "rebind",              FALSE ),
	REQ (NM_DHCP_OPTION_DHCP6_NM_IAID,                          "iaid",                FALSE ),

	{ 0 }
};


const char *
nm_dhcp_option_request_string (const NMDhcpOption *requests, guint option)
{
	guint i = 0;

	while (requests[i].name) {
		if (requests[i].option_num == option)
			return requests[i].name + NM_STRLEN (REQPREFIX);
		i++;
	}

	/* Option should always be found */
	nm_assert_not_reached ();
	return NULL;
}

void
nm_dhcp_option_take_option (GHashTable *options,
             const NMDhcpOption *requests,
             guint option,
             char *value)
{
	nm_assert (options);
	nm_assert (requests);
	nm_assert (value);

	g_hash_table_insert (options,
	                     (gpointer) nm_dhcp_option_request_string (requests, option),
	                     value);
}

void
nm_dhcp_option_add_option (GHashTable *options, const NMDhcpOption *requests, guint option, const char *value)
{
	if (options)
		nm_dhcp_option_take_option (options, requests, option, g_strdup (value));
}

void
nm_dhcp_option_add_option_u64 (GHashTable *options, const NMDhcpOption *requests, guint option, guint64 value)
{
	if (options)
		nm_dhcp_option_take_option (options, requests, option, g_strdup_printf ("%" G_GUINT64_FORMAT, value));
}

void
nm_dhcp_option_add_requests_to_options (GHashTable *options, const NMDhcpOption *requests)
{
	guint i;

	if (!options)
		return;

	for (i = 0; requests[i].name; i++) {
		if (requests[i].include)
			g_hash_table_insert (options, (gpointer) requests[i].name, g_strdup ("1"));
	}
}

GHashTable *
nm_dhcp_option_create_options_dict (void)
{
	return g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, g_free);
}

