/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-dhcp-options.h"

#include "nm-glib-aux/nm-str-buf.h"

/*****************************************************************************/

#define REQ(_num, _name, _include)                                                         \
    {                                                                                      \
        .name = NM_DHCP_OPTION_REQPREFIX ""_name, .option_num = _num, .include = _include, \
    }

const NMDhcpOption _nm_dhcp_option_dhcp4_options[] = {
    REQ(NM_DHCP_OPTION_DHCP4_SUBNET_MASK, "subnet_mask", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_TIME_OFFSET, "time_offset", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_DOMAIN_NAME_SERVER, "domain_name_servers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_HOST_NAME, "host_name", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_DOMAIN_NAME, "domain_name", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_INTERFACE_MTU, "interface_mtu", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_BROADCAST, "broadcast_address", TRUE),
    /* RFC 3442: The Classless Static Routes option code MUST appear in the parameter
     *   request list prior to both the Router option code and the Static
     *   Routes option code, if present. */
    REQ(NM_DHCP_OPTION_DHCP4_CLASSLESS_STATIC_ROUTE, "rfc3442_classless_static_routes", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_ROUTER, "routers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_STATIC_ROUTE, "static_routes", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_NIS_DOMAIN, "nis_domain", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_NIS_SERVERS, "nis_servers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_NTP_SERVER, "ntp_servers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_SERVER_ID, "dhcp_server_identifier", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_DOMAIN_SEARCH_LIST, "domain_search", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE, "ms_classless_static_routes", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY, "wpad", TRUE),
    REQ(NM_DHCP_OPTION_DHCP4_ROOT_PATH, "root_path", TRUE),

    REQ(NM_DHCP_OPTION_DHCP4_TIME_SERVERS, "time_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IEN116_NAME_SERVERS, "ien116_name_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_LOG_SERVERS, "log_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_COOKIE_SERVERS, "cookie_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_LPR_SERVERS, "lpr_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IMPRESS_SERVERS, "impress_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_RESOURCE_LOCATION_SERVERS, "resource_location_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_BOOT_FILE_SIZE, "boot_size", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_MERIT_DUMP, "merit_dump", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SWAP_SERVER, "swap_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_EXTENSIONS_PATH, "extensions_path", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ENABLE_IP_FORWARDING, "ip_forwarding", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ENABLE_SRC_ROUTING, "non_local_source_routing", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_POLICY_FILTER, "policy_filter", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_INTERFACE_MDR, "max_dgram_reassembly", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_INTERFACE_TTL, "default_ip_ttl", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_INTERFACE_MTU_AGING_TIMEOUT, "path_mtu_aging_timeout", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PATH_MTU_PLATEAU_TABLE, "path_mtu_plateau_table", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ALL_SUBNETS_LOCAL, "all_subnets_local", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PERFORM_MASK_DISCOVERY, "perform_mask_discovery", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_MASK_SUPPLIER, "mask_supplier", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ROUTER_DISCOVERY, "router_discovery", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ROUTER_SOLICITATION_ADDR, "router_solicitation_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_TRAILER_ENCAPSULATION, "trailer_encapsulation", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ARP_CACHE_TIMEOUT, "arp_cache_timeout", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IEEE802_3_ENCAPSULATION, "ieee802_3_encapsulation", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_DEFAULT_TCP_TTL, "default_tcp_ttl", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_INTERVAL, "tcp_keepalive_internal", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_TCP_KEEPALIVE_GARBAGE, "tcp_keepalive_garbage", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_VENDOR_SPECIFIC, "vendor_encapsulated_options", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NETBIOS_NAMESERVER, "netbios_name_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NETBIOS_DD_SERVER, "netbios_dd_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_FONT_SERVERS, "font_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_X_DISPLAY_MANAGER, "x_display_manager", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IP_ADDRESS_LEASE_TIME, "dhcp_lease_time", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_RENEWAL_T1_TIME, "dhcp_renewal_time", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_REBINDING_T2_TIME, "dhcp_rebinding_time", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_CLIENT_ID, "dhcp_client_identifier", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NEW_TZDB_TIMEZONE, "tcode", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NWIP_DOMAIN, "nwip_domain", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NWIP_SUBOPTIONS, "nwip_suboptions", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NISPLUS_DOMAIN, "nisplus_domain", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NISPLUS_SERVERS, "nisplus_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_TFTP_SERVER_NAME, "tftp_server_name", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_BOOTFILE_NAME, "bootfile_name", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_MOBILE_IP_HOME_AGENT, "mobile_ip_home_agent", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SMTP_SERVER, "smtp_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_POP_SERVER, "pop_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NNTP_SERVER, "nntp_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_WWW_SERVER, "www_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_FINGER_SERVER, "finger_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IRC_SERVER, "irc_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_STREETTALK_SERVER, "streettalk_server", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_STREETTALK_DIR_ASSIST_SERVER,
        "streettalk_directory_assistance_server",
        FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SLP_DIRECTORY_AGENT, "slp_directory_agent", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SLP_SERVICE_SCOPE, "slp_service_scope", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_CLIENT_FQDN, "fqdn", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_RELAY_AGENT_INFORMATION, "relay_agent_information", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NDS_SERVERS, "nds_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NDS_TREE_NAME, "nds_tree_name", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NDS_CONTEXT, "nds_context", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_NAMES, "bcms_controller_names", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_BCMS_CONTROLLER_ADDRESS, "bcms_controller_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_CLIENT_LAST_TRANSACTION, "client_last_transaction_time", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_ASSOCIATED_IP, "associated_ip", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PXE_SYSTEM_TYPE, "pxe_system_type", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PXE_INTERFACE_ID, "pxe_interface_id", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PXE_CLIENT_ID, "pxe_client_id", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_UAP_SERVERS, "uap_servers", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_GEOCONF_CIVIC, "geoconf_civic", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_ADDRESS, "netinfo_server_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NETINFO_SERVER_TAG, "netinfo_server_tag", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_DEFAULT_URL, "default_url", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_AUTO_CONFIG, "auto_config", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NAME_SERVICE_SEARCH, "name_service_search", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SUBNET_SELECTION, "subnet_selection", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_VIVCO, "vivco", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_VIVSO, "vivso", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PANA_AGENT, "pana_agent", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_V4_LOST, "v4_lost", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_SIP_UA_CS_DOMAINS, "sip_ua_cs_domains", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_IPV4_ADDRESS_ANDSF, "ipv4_address_andsf", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_RDNSS_SELECTION, "rndss_selection", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_TFTP_SERVER_ADDRESS, "tftp_server_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_V4_PORTPARAMS, "v4_portparams", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_V4_CAPTIVE_PORTAL, "v4_captive_portal", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_MUD_URL, "mud_url", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_LOADER_CONFIGFILE, "loader_configfile", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_LOADER_PATHPREFIX, "loader_pathprefix", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_LOADER_REBOOTTIME, "loader_reboottime", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_OPTION_6RD, "option_6rd", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_V4_ACCESS_DOMAIN, "v4_access_domain", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_224, "private_224", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_225, "private_225", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_226, "private_226", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_227, "private_227", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_228, "private_228", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_229, "private_229", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_230, "private_230", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_231, "private_231", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_232, "private_232", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_233, "private_233", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_234, "private_234", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_235, "private_235", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_236, "private_236", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_237, "private_237", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_238, "private_238", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_239, "private_239", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_240, "private_240", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_241, "private_241", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_242, "private_242", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_243, "private_243", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_244, "private_244", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_245, "private_245", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_246, "private_246", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_247, "private_247", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_248, "private_248", FALSE),
    /* NM_DHCP_OPTION_DHCP4_PRIVATE_CLASSLESS_STATIC_ROUTE */
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_250, "private_250", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_251, "private_251", FALSE),
    /* NM_DHCP_OPTION_DHCP4_PRIVATE_PROXY_AUTODISCOVERY */
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_253, "private_253", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_PRIVATE_254, "private_254", FALSE),

    /* Internal values */
    REQ(NM_DHCP_OPTION_DHCP4_NM_IP_ADDRESS, "ip_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NM_EXPIRY, "expiry", FALSE),
    REQ(NM_DHCP_OPTION_DHCP4_NM_NEXT_SERVER, "next_server", FALSE),
};

static const NMDhcpOption *const _sorted_options_4[G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options)] = {
#define A(idx) (&_nm_dhcp_option_dhcp4_options[(idx)])
    A(0),   A(1),   A(8),   A(18),  A(19),  A(2),   A(20),  A(21),  A(22),  A(23),  A(24),  A(3),
    A(25),  A(26),  A(4),   A(27),  A(17),  A(28),  A(29),  A(30),  A(31),  A(32),  A(33),  A(34),
    A(35),  A(5),   A(36),  A(6),   A(37),  A(38),  A(39),  A(40),  A(9),   A(41),  A(42),  A(43),
    A(44),  A(45),  A(46),  A(10),  A(11),  A(12),  A(47),  A(48),  A(49),  A(50),  A(51),  A(52),
    A(13),  A(53),  A(54),  A(55),  A(57),  A(58),  A(59),  A(60),  A(61),  A(62),  A(63),  A(64),
    A(65),  A(66),  A(67),  A(68),  A(69),  A(70),  A(71),  A(72),  A(73),  A(74),  A(75),  A(76),
    A(77),  A(78),  A(79),  A(80),  A(81),  A(82),  A(83),  A(84),  A(85),  A(86),  A(87),  A(56),
    A(88),  A(89),  A(90),  A(91),  A(92),  A(93),  A(14),  A(7),   A(94),  A(95),  A(96),  A(97),
    A(98),  A(99),  A(100), A(101), A(102), A(103), A(104), A(105), A(106), A(107), A(108), A(109),
    A(110), A(111), A(112), A(113), A(114), A(115), A(116), A(117), A(118), A(119), A(120), A(121),
    A(122), A(123), A(124), A(125), A(126), A(127), A(128), A(129), A(130), A(131), A(132), A(133),
    A(134), A(15),  A(135), A(136), A(16),  A(137), A(138), A(139), A(140), A(141),
#undef A
};

const NMDhcpOption _nm_dhcp_option_dhcp6_options[] = {
    REQ(NM_DHCP_OPTION_DHCP6_CLIENTID, "dhcp6_client_id", FALSE),

    /* Don't request server ID by default; some servers don't reply to
     * Information Requests that request the Server ID.
     */
    REQ(NM_DHCP_OPTION_DHCP6_SERVERID, "dhcp6_server_id", FALSE),

    REQ(NM_DHCP_OPTION_DHCP6_DNS_SERVERS, "dhcp6_name_servers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP6_DOMAIN_LIST, "dhcp6_domain_search", TRUE),
    REQ(NM_DHCP_OPTION_DHCP6_SNTP_SERVERS, "dhcp6_sntp_servers", TRUE),
    REQ(NM_DHCP_OPTION_DHCP6_FQDN, "fqdn_fqdn", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_MUD_URL, "dhcp6_mud_url", FALSE),

    /* Internal values */
    REQ(NM_DHCP_OPTION_DHCP6_NM_IP_ADDRESS, "ip6_address", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_PREFIXLEN, "ip6_prefixlen", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_PREFERRED_LIFE, "preferred_life", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_MAX_LIFE, "max_life", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_STARTS, "starts", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_LIFE_STARTS, "life_starts", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_RENEW, "renew", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_REBIND, "rebind", FALSE),
    REQ(NM_DHCP_OPTION_DHCP6_NM_IAID, "iaid", FALSE),
};

#undef REQ

static const NMDhcpOption *const _sorted_options_6[G_N_ELEMENTS(_nm_dhcp_option_dhcp6_options)] = {
#define A(idx) (&_nm_dhcp_option_dhcp6_options[(idx)])
    A(0),
    A(1),
    A(2),
    A(3),
    A(4),
    A(5),
    A(6),
    A(7),
    A(8),
    A(9),
    A(10),
    A(11),
    A(12),
    A(13),
    A(14),
    A(15),
#undef A
};

/*****************************************************************************/

static int
_sorted_options_generate_sort(gconstpointer pa, gconstpointer pb, gpointer user_data)
{
    const NMDhcpOption *const *a = pa;
    const NMDhcpOption *const *b = pb;

    NM_CMP_DIRECT((*a)->option_num, (*b)->option_num);
    return nm_assert_unreachable_val(0);
}

static char *
_sorted_options_generate(const NMDhcpOption *base, const NMDhcpOption *const *sorted, guint n)
{
    gs_free const NMDhcpOption **sort2 = NULL;
    NMStrBuf                     sbuf  = NM_STR_BUF_INIT(0, FALSE);
    guint                        i;

    sort2 = nm_memdup(sorted, n * sizeof(sorted[0]));

    g_qsort_with_data(sort2, n, sizeof(sort2[0]), _sorted_options_generate_sort, NULL);

    for (i = 0; i < n; i++) {
        if (i > 0)
            nm_str_buf_append(&sbuf, ", ");
        nm_str_buf_append_printf(&sbuf, "A(%d)", (int) (sort2[i] - base));
    }

    return nm_str_buf_finalize(&sbuf, NULL);
}

_nm_unused static void
_ASSERT_sorted(int IS_IPv4, const NMDhcpOption *const *const sorted, int n)

{
    const NMDhcpOption *const options =
        IS_IPv4 ? _nm_dhcp_option_dhcp4_options : _nm_dhcp_option_dhcp6_options;
    int           i;
    int           j;
    gs_free char *sorted_msg = NULL;

    for (i = 0; i < n; i++) {
        const NMDhcpOption *opt = sorted[i];

        g_assert(opt);
        g_assert(opt >= options);
        g_assert(opt < &options[n]);

        for (j = 0; j < i; j++) {
            const NMDhcpOption *opt2 = sorted[j];

            if (opt == opt2) {
                g_error("%s:%d: the _sorted_options_%c at [%d] (opt=%u, %s) is duplicated at "
                        "[%d] (SORT: %s)",
                        __FILE__,
                        __LINE__,
                        IS_IPv4 ? '4' : '6',
                        i,
                        opt->option_num,
                        opt->name,
                        j,
                        (sorted_msg = _sorted_options_generate(options, sorted, n)));
            }
        }

        if (i > 0) {
            const NMDhcpOption *opt2 = sorted[i - 1];

            if (opt2->option_num >= opt->option_num) {
                g_error("%s:%d: the _sorted_options_%c at [%d] (opt=%u, %s) should come before "
                        "[%d] (opt=%u, %s) (SORT: %s)",
                        __FILE__,
                        __LINE__,
                        IS_IPv4 ? '4' : '6',
                        i,
                        opt->option_num,
                        opt->name,
                        i - 1,
                        opt2->option_num,
                        opt2->name,
                        (sorted_msg = _sorted_options_generate(options, sorted, n)));
            }
        }
    }
}

/*****************************************************************************/

const NMDhcpOption *
nm_dhcp_option_find(int addr_family, guint option)
{
    const int                        IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMDhcpOption *const *const sorted  = IS_IPv4 ? _sorted_options_4 : _sorted_options_6;
    const int                        n       = IS_IPv4 ? G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options)
                                                       : G_N_ELEMENTS(_nm_dhcp_option_dhcp6_options);
    int                              imin    = 0;
    int                              imax    = n - 1;
    int                              imid    = (n - 1) / 2;

#if NM_MORE_ASSERTS > 10
    nm_assert(n < G_MAXINT / 2);
    if (IS_IPv4 && !NM_MORE_ASSERT_ONCE(10)) {
        /* already checked */
    } else if (!IS_IPv4 && !NM_MORE_ASSERT_ONCE(10)) {
        /* already checked */
    } else
        _ASSERT_sorted(IS_IPv4, sorted, n);
#endif

    for (;;) {
        const guint o = sorted[imid]->option_num;

        if (G_UNLIKELY(o == option))
            return sorted[imid];

        if (o < option)
            imin = imid + 1;
        else
            imax = imid - 1;

        if (G_UNLIKELY(imin > imax))
            break;

        imid = (imin + imax) / 2;
    }

    /* Option should always be found */
    return nm_assert_unreachable_val(NULL);
}

/*****************************************************************************/

void
nm_dhcp_option_take_option(GHashTable *options, int addr_family, guint option, char *value)
{
    nm_assert_addr_family(addr_family);
    nm_assert(value);
    nm_assert(g_utf8_validate(value, -1, NULL));

    if (!options) {
        nm_assert_not_reached();
        g_free(value);
        return;
    }

    g_hash_table_insert(options,
                        (gpointer) nm_dhcp_option_request_string(addr_family, option),
                        value);
}

void
nm_dhcp_option_add_option(GHashTable *options, int addr_family, guint option, const char *value)
{
    nm_dhcp_option_take_option(options, addr_family, option, g_strdup(value));
}

void
nm_dhcp_option_add_option_utf8safe_escape(GHashTable *  options,
                                          int           addr_family,
                                          guint         option,
                                          const guint8 *data,
                                          gsize         n_data)
{
    gs_free char *to_free = NULL;
    const char *  escaped;

    escaped = nm_utils_buf_utf8safe_escape((char *) data, n_data, 0, &to_free);
    nm_dhcp_option_add_option(options, addr_family, option, escaped ?: "");
}

void
nm_dhcp_option_add_option_u64(GHashTable *options, int addr_family, guint option, guint64 value)
{
    nm_dhcp_option_take_option(options,
                               addr_family,
                               option,
                               g_strdup_printf("%" G_GUINT64_FORMAT, value));
}

void
nm_dhcp_option_add_option_in_addr(GHashTable *options,
                                  int         addr_family,
                                  guint       option,
                                  in_addr_t   value)
{
    char sbuf[NM_UTILS_INET_ADDRSTRLEN];

    nm_dhcp_option_add_option(options, addr_family, option, _nm_utils_inet4_ntop(value, sbuf));
}

void
nm_dhcp_option_add_requests_to_options(GHashTable *options, int addr_family)
{
    const int                 IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMDhcpOption *const all_options =
        IS_IPv4 ? _nm_dhcp_option_dhcp4_options : _nm_dhcp_option_dhcp6_options;
    int n_options = IS_IPv4 ? G_N_ELEMENTS(_nm_dhcp_option_dhcp4_options)
                            : G_N_ELEMENTS(_nm_dhcp_option_dhcp6_options);
    int i;

    for (i = 0; i < n_options; i++) {
        if (all_options[i].include)
            g_hash_table_insert(options, (gpointer) all_options[i].name, g_strdup("1"));
    }
}

GHashTable *
nm_dhcp_option_create_options_dict(void)
{
    return g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, g_free);
}
