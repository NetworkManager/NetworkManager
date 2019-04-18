/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <glib-unix.h>
#include <getopt.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>
#include <linux/rtnetlink.h>

#include "nm-glib-aux/nm-c-list.h"

#include "main-utils.h"
#include "NetworkManagerUtils.h"
#include "platform/nm-linux-platform.h"
#include "platform/nm-platform-utils.h"
#include "dhcp/nm-dhcp-manager.h"
#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-lndp-ndisc.h"
#include "nm-utils.h"
#include "nm-setting-ip6-config.h"
#include "systemd/nm-sd.h"

#if !defined(NM_DIST_VERSION)
# define NM_DIST_VERSION VERSION
#endif

#define NMIH_PID_FILE_FMT NMRUNDIR "/nm-iface-helper-%d.pid"

/*****************************************************************************/

static struct {
	GMainLoop *main_loop;
	int ifindex;

	guint dad_failed_id;
	CList dad_failed_lst_head;
} gl/*obal*/ = {
	.ifindex = -1,
};

static struct {
	gboolean slaac;
	gboolean show_version;
	gboolean become_daemon;
	gboolean debug;
	gboolean g_fatal_warnings;
	gboolean slaac_required;
	gboolean dhcp4_required;
	int tempaddr;
	char *ifname;
	char *uuid;
	char *stable_id;
	char *dhcp4_address;
	char *dhcp4_clientid;
	char *dhcp4_hostname;
	char *dhcp4_fqdn;
	char *iid_str;
	NMSettingIP6ConfigAddrGenMode addr_gen_mode;
	char *logging_backend;
	char *opt_log_level;
	char *opt_log_domains;
	guint32 priority_v4;
	guint32 priority_v6;
} global_opt = {
	.tempaddr = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
	.priority_v4 = NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4,
	.priority_v6 = NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
};

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "nm-iface-helper"
#define _NMLOG(level, domain, ...) \
    nm_log ((level), (domain), global_opt.ifname, NULL, \
            "iface-helper: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static void
dhcp4_state_changed (NMDhcpClient *client,
                     NMDhcpState state,
                     NMIP4Config *ip4_config,
                     GHashTable *options,
                     const char *event_id,
                     gpointer user_data)
{
	static NMIP4Config *last_config = NULL;
	NMIP4Config *existing;
	gs_unref_ptrarray GPtrArray *ip4_dev_route_blacklist = NULL;

	g_return_if_fail (!ip4_config || NM_IS_IP4_CONFIG (ip4_config));

	_LOGD (LOGD_DHCP4, "new DHCPv4 client state %d", state);

	switch (state) {
	case NM_DHCP_STATE_BOUND:
		g_assert (ip4_config);
		g_assert (nm_ip4_config_get_ifindex (ip4_config) == gl.ifindex);

		existing = nm_ip4_config_capture (nm_platform_get_multi_idx (NM_PLATFORM_GET),
		                                  NM_PLATFORM_GET, gl.ifindex);
		if (last_config)
			nm_ip4_config_subtract (existing, last_config, 0);

		nm_ip4_config_merge (existing, ip4_config, NM_IP_CONFIG_MERGE_DEFAULT, 0);
		nm_ip4_config_add_dependent_routes (existing,
		                                    RT_TABLE_MAIN,
		                                    global_opt.priority_v4,
		                                    &ip4_dev_route_blacklist);
		if (!nm_ip4_config_commit (existing,
		                           NM_PLATFORM_GET,
		                           NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN))
			_LOGW (LOGD_DHCP4, "failed to apply DHCPv4 config");

		nm_platform_ip4_dev_route_blacklist_set (NM_PLATFORM_GET,
		                                         gl.ifindex,
		                                         ip4_dev_route_blacklist);

		if (last_config)
			g_object_unref (last_config);
		last_config = nm_ip4_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET),
		                                 nm_dhcp_client_get_ifindex (client));
		nm_ip4_config_replace (last_config, ip4_config, NULL);
		break;
	case NM_DHCP_STATE_TIMEOUT:
	case NM_DHCP_STATE_DONE:
	case NM_DHCP_STATE_FAIL:
		if (global_opt.dhcp4_required) {
			_LOGW (LOGD_DHCP4, "DHCPv4 timed out or failed, quitting...");
			g_main_loop_quit (gl.main_loop);
		} else
			_LOGW (LOGD_DHCP4, "DHCPv4 timed out or failed");
		break;
	default:
		break;
	}
}

static void
ndisc_config_changed (NMNDisc *ndisc, const NMNDiscData *rdata, guint changed_int, gpointer user_data)
{
	NMNDiscConfigMap changed = changed_int;
	static NMIP6Config *ndisc_config = NULL;
	NMIP6Config *existing;

	existing = nm_ip6_config_capture (nm_platform_get_multi_idx (NM_PLATFORM_GET),
	                                  NM_PLATFORM_GET, gl.ifindex, global_opt.tempaddr);
	if (ndisc_config)
		nm_ip6_config_subtract (existing, ndisc_config, 0);
	else {
		ndisc_config = nm_ip6_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET),
		                                  gl.ifindex);
	}

	if (changed & NM_NDISC_CONFIG_ADDRESSES) {
		guint8 plen;
		guint32 ifa_flags;

		/* Check, whether kernel is recent enough to help user space handling RA.
		 * If it's not supported, we have no ipv6-privacy and must add autoconf
		 * addresses as /128. The reason for the /128 is to prevent the kernel
		 * from adding a prefix route for this address. */
		ifa_flags = 0;
		if (nm_platform_kernel_support_get (NM_PLATFORM_KERNEL_SUPPORT_TYPE_EXTENDED_IFA_FLAGS)) {
			ifa_flags |= IFA_F_NOPREFIXROUTE;
			if (NM_IN_SET (global_opt.tempaddr, NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR,
			                                    NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR))
				ifa_flags |= IFA_F_MANAGETEMPADDR;
			plen = 64;
		} else
			plen = 128;

		nm_ip6_config_reset_addresses_ndisc (ndisc_config,
		                                     rdata->addresses,
		                                     rdata->addresses_n,
		                                     plen,
		                                     ifa_flags);
	}

	if (NM_FLAGS_ANY (changed,  NM_NDISC_CONFIG_ROUTES
	                          | NM_NDISC_CONFIG_GATEWAYS)) {
		nm_ip6_config_reset_routes_ndisc (ndisc_config,
		                                  rdata->gateways,
		                                  rdata->gateways_n,
		                                  rdata->routes,
		                                  rdata->routes_n,
		                                  RT_TABLE_MAIN,
		                                  global_opt.priority_v6,
		                                  nm_platform_kernel_support_get (NM_PLATFORM_KERNEL_SUPPORT_TYPE_RTA_PREF));
	}

	if (changed & NM_NDISC_CONFIG_DHCP_LEVEL) {
		/* Unsupported until systemd DHCPv6 is ready */
	}

	if (changed & NM_NDISC_CONFIG_HOP_LIMIT)
		nm_platform_sysctl_ip_conf_set_ipv6_hop_limit_safe (NM_PLATFORM_GET, global_opt.ifname, rdata->hop_limit);

	if (changed & NM_NDISC_CONFIG_MTU) {
		nm_platform_sysctl_ip_conf_set_int64 (NM_PLATFORM_GET,
		                                      AF_INET6,
		                                      global_opt.ifname,
		                                      "mtu",
		                                      rdata->mtu);
	}

	nm_ip6_config_merge (existing, ndisc_config, NM_IP_CONFIG_MERGE_DEFAULT, 0);
	nm_ip6_config_add_dependent_routes (existing,
	                                    RT_TABLE_MAIN,
	                                    global_opt.priority_v6);
	if (!nm_ip6_config_commit (existing,
	                           NM_PLATFORM_GET,
	                           NM_IP_ROUTE_TABLE_SYNC_MODE_MAIN,
	                           NULL))
		_LOGW (LOGD_IP6, "failed to apply IPv6 config");
}

static void
ndisc_ra_timeout (NMNDisc *ndisc, gpointer user_data)
{
	if (global_opt.slaac_required) {
		_LOGW (LOGD_IP6, "IPv6 timed out or failed, quitting...");
		g_main_loop_quit (gl.main_loop);
	} else
		_LOGW (LOGD_IP6, "IPv6 timed out or failed");
}

static gboolean
quit_handler (gpointer user_data)
{
	g_main_loop_quit (gl.main_loop);
	return G_SOURCE_REMOVE;
}

static void
setup_signals (void)
{
	signal (SIGPIPE, SIG_IGN);
	g_unix_signal_add (SIGINT, quit_handler, NULL);
	g_unix_signal_add (SIGTERM, quit_handler, NULL);
}

static gboolean
do_early_setup (int *argc, char **argv[])
{
	gint64 priority64_v4 = -1;
	gint64 priority64_v6 = -1;
	GOptionEntry options[] = {
		/* Interface/IP config */
		{ "ifname", 'i', 0, G_OPTION_ARG_STRING, &global_opt.ifname, N_("The interface to manage"), "eth0" },
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &global_opt.uuid, N_("Connection UUID"),  "661e8cd0-b618-46b8-9dc9-31a52baaa16b" },
		{ "stable-id", '\0', 0, G_OPTION_ARG_STRING, &global_opt.stable_id, N_("Connection Token for Stable IDs"),  "eth" },
		{ "slaac", 's', 0, G_OPTION_ARG_NONE, &global_opt.slaac, N_("Whether to manage IPv6 SLAAC"), NULL },
		{ "slaac-required", '6', 0, G_OPTION_ARG_NONE, &global_opt.slaac_required, N_("Whether SLAAC must be successful"), NULL },
		{ "slaac-tempaddr", 't', 0, G_OPTION_ARG_INT, &global_opt.tempaddr, N_("Use an IPv6 temporary privacy address"), NULL },
		{ "dhcp4", 'd', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_address, N_("Current DHCPv4 address"), NULL },
		{ "dhcp4-required", '4', 0, G_OPTION_ARG_NONE, &global_opt.dhcp4_required, N_("Whether DHCPv4 must be successful"), NULL },
		{ "dhcp4-clientid", 'c', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_clientid, N_("Hex-encoded DHCPv4 client ID"), NULL },
		{ "dhcp4-hostname", 'h', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_hostname, N_("Hostname to send to DHCP server"), N_("barbar") },
		{ "dhcp4-fqdn",     'F', 0, G_OPTION_ARG_STRING, &global_opt.dhcp4_fqdn, N_("FQDN to send to DHCP server"), N_("host.domain.org") },
		{ "priority4", '\0', 0, G_OPTION_ARG_INT64, &priority64_v4, N_("Route priority for IPv4"), N_("0") },
		{ "priority6", '\0', 0, G_OPTION_ARG_INT64, &priority64_v6, N_("Route priority for IPv6"), N_("1024") },
		{ "iid", 'e', 0, G_OPTION_ARG_STRING, &global_opt.iid_str, N_("Hex-encoded Interface Identifier"), "" },
		{ "addr-gen-mode", 'e', 0, G_OPTION_ARG_INT, &global_opt.addr_gen_mode, N_("IPv6 SLAAC address generation mode"), "eui64" },
		{ "logging-backend", '\0', 0, G_OPTION_ARG_STRING, &global_opt.logging_backend, N_("The logging backend configuration value. See logging.backend in NetworkManager.conf"), NULL },

		/* Logging/debugging */
		{ "version", 'V', 0, G_OPTION_ARG_NONE, &global_opt.show_version, N_("Print NetworkManager version and exit"), NULL },
		{ "no-daemon", 'n', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &global_opt.become_daemon, N_("Don't become a daemon"), NULL },
		{ "debug", 'b', 0, G_OPTION_ARG_NONE, &global_opt.debug, N_("Don't become a daemon, and log to stderr"), NULL },
		{ "log-level", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_level, N_("Log level: one of [%s]"), "INFO" },
		{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &global_opt.opt_log_domains,
		  N_("Log domains separated by ',': any combination of [%s]"),
		  "PLATFORM,RFKILL,WIFI" },
		{ "g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &global_opt.g_fatal_warnings, N_("Make all warnings fatal"), NULL },
		{NULL}
	};

	if (!nm_main_utils_early_setup ("nm-iface-helper",
	                                argc,
	                                argv,
	                                options,
	                                NULL,
	                                NULL,
	                                _("nm-iface-helper is a small, standalone process that manages a single network interface.")))
		return FALSE;

	if (priority64_v4 >= 0 && priority64_v4 <= G_MAXUINT32)
		global_opt.priority_v4 = (guint32) priority64_v4;
	if (priority64_v6 >= 0 && priority64_v6 <= G_MAXUINT32)
		global_opt.priority_v6 = (guint32) priority64_v6;
	return TRUE;
}

typedef struct {
	NMPlatform *platform;
	NMNDisc *ndisc;
} DadFailedHandleData;

static gboolean
dad_failed_handle_idle (gpointer user_data)
{
	DadFailedHandleData *data = user_data;
	NMCListElem *elem;

	while ((elem = c_list_first_entry (&gl.dad_failed_lst_head, NMCListElem, lst))) {
		nm_auto_nmpobj const NMPObject *obj = elem->data;

		nm_c_list_elem_free (elem);

		if (nm_ndisc_dad_addr_is_fail_candidate (data->platform, obj)) {
			nm_ndisc_dad_failed (data->ndisc,
			                     &NMP_OBJECT_CAST_IP6_ADDRESS (obj)->address,
			                     TRUE);
		}
	}

	gl.dad_failed_id = 0;
	return G_SOURCE_REMOVE;
}

static void
ip6_address_changed (NMPlatform *platform,
                     int obj_type_i,
                     int iface,
                     const NMPlatformIP6Address *addr,
                     int change_type_i,
                     NMNDisc *ndisc)
{
	const NMPlatformSignalChangeType change_type = change_type_i;
	DadFailedHandleData *data;

	if (!nm_ndisc_dad_addr_is_fail_candidate_event (change_type, addr))
		return;

	c_list_link_tail (&gl.dad_failed_lst_head,
	                  &nm_c_list_elem_new_stale ((gpointer) nmp_object_ref (NMP_OBJECT_UP_CAST (addr)))->lst);
	if (gl.dad_failed_id)
		return;

	data = g_slice_new (DadFailedHandleData);
	data->platform = platform;
	data->ndisc = ndisc;
	gl.dad_failed_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
	                                    dad_failed_handle_idle,
	                                    data,
	                                    nm_g_slice_free_fcn (DadFailedHandleData));
}

int
main (int argc, char *argv[])
{
	char *bad_domains = NULL;
	gs_free_error GError *error = NULL;
	gboolean wrote_pidfile = FALSE;
	gs_free char *pidfile = NULL;
	gs_unref_object NMDhcpClient *dhcp4_client = NULL;
	gs_unref_object NMNDisc *ndisc = NULL;
	gs_unref_bytes GBytes *hwaddr = NULL;
	gs_unref_bytes GBytes *client_id = NULL;
	gs_free NMUtilsIPv6IfaceId *iid = NULL;
	guint sd_id;
	int errsv;

	c_list_init (&gl.dad_failed_lst_head);

	setpgid (getpid (), getpid ());

	if (!do_early_setup (&argc, &argv))
		return 1;

	nm_logging_init_pre ("nm-iface-helper",
	                     g_strdup_printf ("%s[%ld] (%s): ",
	                                      _NMLOG_PREFIX_NAME,
	                                      (long) getpid (),
	                                      global_opt.ifname ?: "???"));

	if (global_opt.g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	if (global_opt.show_version) {
		fprintf (stdout, NM_DIST_VERSION "\n");
		return 0;
	}

	nm_main_utils_ensure_root ();

	if (!global_opt.ifname || !global_opt.uuid) {
		fprintf (stderr, _("An interface name and UUID are required\n"));
		return 1;
	}

	gl.ifindex = nmp_utils_if_nametoindex (global_opt.ifname);
	if (gl.ifindex <= 0) {
		errsv = errno;
		fprintf (stderr, _("Failed to find interface index for %s (%s)\n"), global_opt.ifname, nm_strerror_native (errsv));
		return 1;
	}
	pidfile = g_strdup_printf (NMIH_PID_FILE_FMT, gl.ifindex);
	nm_main_utils_ensure_not_running_pidfile (pidfile);

	nm_main_utils_ensure_rundir ();

	if (!nm_logging_setup (global_opt.opt_log_level,
	                       global_opt.opt_log_domains,
	                       &bad_domains,
	                       &error)) {
		fprintf (stderr,
		         _("%s.  Please use --help to see a list of valid options.\n"),
		         error->message);
		return 1;
	} else if (bad_domains) {
		fprintf (stderr,
		         _("Ignoring unrecognized log domain(s) '%s' passed on command line.\n"),
		         bad_domains);
		g_clear_pointer (&bad_domains, g_free);
	}

	if (global_opt.become_daemon && !global_opt.debug) {
		if (daemon (0, 0) < 0) {
			errsv = errno;
			fprintf (stderr, _("Could not daemonize: %s [error %u]\n"),
			         nm_strerror_native (errsv),
			         errsv);
			return 1;
		}
		if (nm_main_utils_write_pidfile (pidfile))
			wrote_pidfile = TRUE;
	}

	/* Set up unix signal handling - before creating threads, but after daemonizing! */
	gl.main_loop = g_main_loop_new (NULL, FALSE);
	setup_signals ();

	nm_logging_init (global_opt.logging_backend,
	                 global_opt.debug);

	_LOGI (LOGD_CORE, "nm-iface-helper (version " NM_DIST_VERSION ") is starting...");

	/* Set up platform interaction layer */
	nm_linux_platform_setup ();

	hwaddr = nm_platform_link_get_address_as_bytes (NM_PLATFORM_GET, gl.ifindex);

	if (global_opt.iid_str) {
		GBytes *bytes;
		gsize ignored = 0;

		bytes = nm_utils_hexstr2bin (global_opt.iid_str);
		if (!bytes || g_bytes_get_size (bytes) != sizeof (*iid)) {
			fprintf (stderr, _("(%s): Invalid IID %s\n"), global_opt.ifname, global_opt.iid_str);
			return 1;
		}
		iid = g_bytes_unref_to_data (bytes, &ignored);
	}

	if (global_opt.dhcp4_clientid) {
		/* this string is just a plain hex-string. Unlike ipv4.dhcp-client-id, which
		 * is parsed via nm_dhcp_utils_client_id_string_to_bytes(). */
		client_id = nm_utils_hexstr2bin (global_opt.dhcp4_clientid);
		if (!client_id || g_bytes_get_size (client_id) < 2) {
			fprintf (stderr, _("(%s): Invalid DHCP client-id %s\n"), global_opt.ifname, global_opt.dhcp4_clientid);
			return 1;
		}
	}

	if (global_opt.dhcp4_address) {
		nm_platform_sysctl_ip_conf_set (NM_PLATFORM_GET,
		                                AF_INET,
		                                global_opt.ifname,
		                                "promote_secondaries",
		                                "1");

		dhcp4_client = nm_dhcp_manager_start_ip4 (nm_dhcp_manager_get (),
		                                          nm_platform_get_multi_idx (NM_PLATFORM_GET),
		                                          global_opt.ifname,
		                                          gl.ifindex,
		                                          hwaddr,
		                                          global_opt.uuid,
		                                          RT_TABLE_MAIN,
		                                          global_opt.priority_v4,
		                                          !!global_opt.dhcp4_hostname,
		                                          global_opt.dhcp4_hostname,
		                                          global_opt.dhcp4_fqdn,
		                                          client_id,
		                                          NM_DHCP_TIMEOUT_DEFAULT,
		                                          NULL,
		                                          global_opt.dhcp4_address,
		                                          &error);
		if (!dhcp4_client)
			g_error ("failure to start DHCP: %s", error->message);

		g_signal_connect (dhcp4_client,
		                  NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
		                  G_CALLBACK (dhcp4_state_changed),
		                  NULL);
	}

	if (global_opt.slaac) {
		NMUtilsStableType stable_type = NM_UTILS_STABLE_TYPE_UUID;
		const char *stable_id = global_opt.uuid;

		nm_platform_link_set_user_ipv6ll_enabled (NM_PLATFORM_GET, gl.ifindex, TRUE);

		if (   global_opt.stable_id
		    && (global_opt.stable_id[0] >= '0' && global_opt.stable_id[0] <= '9')
		    && global_opt.stable_id[1] == ' ') {
			/* strict parsing of --stable-id, which is the numeric stable-type
			 * and the ID, joined with one space. For now, only support stable-types
			 * from 0 to 9. */
			stable_type = (global_opt.stable_id[0] - '0');
			stable_id = &global_opt.stable_id[2];
		}
		ndisc = nm_lndp_ndisc_new (NM_PLATFORM_GET, gl.ifindex, global_opt.ifname,
		                           stable_type, stable_id,
		                           global_opt.addr_gen_mode,
		                           NM_NDISC_NODE_TYPE_HOST,
		                           NULL);
		g_assert (ndisc);

		if (iid)
			nm_ndisc_set_iid (ndisc, *iid);

		nm_platform_sysctl_ip_conf_set (NM_PLATFORM_GET, AF_INET6, global_opt.ifname, "accept_ra",          "1");
		nm_platform_sysctl_ip_conf_set (NM_PLATFORM_GET, AF_INET6, global_opt.ifname, "accept_ra_defrtr",   "0");
		nm_platform_sysctl_ip_conf_set (NM_PLATFORM_GET, AF_INET6, global_opt.ifname, "accept_ra_pinfo",    "0");
		nm_platform_sysctl_ip_conf_set (NM_PLATFORM_GET, AF_INET6, global_opt.ifname, "accept_ra_rtr_pref", "0");

		g_signal_connect (NM_PLATFORM_GET,
		                  NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
		                  G_CALLBACK (ip6_address_changed),
		                  ndisc);
		g_signal_connect (ndisc,
		                  NM_NDISC_CONFIG_RECEIVED,
		                  G_CALLBACK (ndisc_config_changed),
		                  NULL);
		g_signal_connect (ndisc,
		                  NM_NDISC_RA_TIMEOUT,
		                  G_CALLBACK (ndisc_ra_timeout),
		                  NULL);
		nm_ndisc_start (ndisc);
	}

	sd_id = nm_sd_event_attach_default ();

	g_main_loop_run (gl.main_loop);

	nm_clear_g_source (&gl.dad_failed_id);
	nm_c_list_elem_free_all (&gl.dad_failed_lst_head, (GDestroyNotify) nmp_object_unref);

	if (pidfile && wrote_pidfile)
		unlink (pidfile);

	_LOGI (LOGD_CORE, "exiting");

	nm_clear_g_source (&sd_id);
	g_clear_pointer (&gl.main_loop, g_main_loop_unref);
	return 0;
}

/*****************************************************************************/

const NMDhcpClientFactory *const _nm_dhcp_manager_factories[4] = {
	&_nm_dhcp_client_factory_internal,
};

/*****************************************************************************/
/* Stub functions */

#include "nm-config.h"
#include "devices/nm-device.h"
#include "nm-active-connection.h"
#include "nm-dbus-manager.h"

void
nm_main_config_reload (int signal)
{
	_LOGI (LOGD_CORE, "reloading configuration not supported");
}

NMConfig *
nm_config_get (void)
{
	return GUINT_TO_POINTER (1);
}

NMConfigData *
nm_config_get_data_orig (NMConfig *config)
{
	return GUINT_TO_POINTER (1);
}

char *
nm_config_data_get_value (const NMConfigData *config_data, const char *group, const char *key, NMConfigGetValueFlags flags)
{
	return NULL;
}

NMConfigConfigureAndQuitType
nm_config_get_configure_and_quit (NMConfig *config)
{
	return NM_CONFIG_CONFIGURE_AND_QUIT_ENABLED;
}

NMDBusManager *
nm_dbus_manager_get (void)
{
	return NULL;
}

gboolean
nm_dbus_manager_is_stopping (NMDBusManager *self)
{
	return FALSE;
}

void
_nm_dbus_manager_obj_export (NMDBusObject *obj)
{
}

void
_nm_dbus_manager_obj_unexport (NMDBusObject *obj)
{
}

void
_nm_dbus_manager_obj_notify (NMDBusObject *obj,
                             guint n_pspecs,
                             const GParamSpec *const*pspecs)
{
}

void
_nm_dbus_manager_obj_emit_signal (NMDBusObject *obj,
                                  const NMDBusInterfaceInfoExtended *interface_info,
                                  const GDBusSignalInfo *signal_info,
                                  GVariant *args)
{
}

GType
nm_device_get_type (void)
{
	g_return_val_if_reached (0);
}

GType
nm_active_connection_get_type (void)
{
	g_return_val_if_reached (0);
}

